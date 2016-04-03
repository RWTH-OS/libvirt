/*
 * lxctools_migration.c: functions for migratiing lxctools domains
 *
 * Copyright (C) 2015 Niklas Eiling
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Authors:
 * Niklas Eiling <niklas.eiling@rwth-aachen.de>
 *
 */
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lxc/lxccontainer.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>

#include "viralloc.h"
#include "vircommand.h"
#include "virfile.h"
#include "lxctools_conf.h"
#include "virlog.h"
#include "lxctools_migration.h"
#include "virstring.h"
#include "time.h"

#define VIR_FROM_THIS VIR_FROM_LXCTOOLS

VIR_LOG_INIT("lxctools.lxctools_migration");


int restoreContainer(struct lxc_container *cont, bool live)
{
    char *tmpfs_path = NULL;
    char tmpfs_suffix[16] = "migrate_tmpfs";
    int ret = -1;

    if (live)
        sprintf(tmpfs_suffix, "migrate_tmpfs/%d", LXCTOOLS_LIVE_MIGRATION_ITERATIONS);

    if ((tmpfs_path = concatPaths(cont->get_config_path(cont),
                                  tmpfs_suffix)) == NULL)
        goto cleanup;

	struct migrate_opts opts;
	opts.directory = tmpfs_path;
	opts.verbose = true;
	opts.stop = false;
	opts.pageserver_address = NULL;
	opts.pageserver_port = NULL;
	opts.predump_dir = NULL;

    if (cont->migrate(cont, MIGRATE_RESTORE, &opts, sizeof(opts))!=0) {
		virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                            _("lxc api call failed. check lxc log for more information"));
        goto cleanup;
    }


    if (!cont->is_running(cont)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("something went wrong while restoring"));
        goto cleanup;
    }
    ret = 0;
 cleanup:
    VIR_FREE(tmpfs_path);
    return ret;
}

bool createTmpfs(const char* path)
{
    bool ret;
    unsigned long mountflags = MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID;
    if (!virFileExists(path)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("path '%s' does not exist"),
                       path);
        return false;
    }

    if (!virFileIsDir(path)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("path '%s' does not point to a directory"),
                       path);
        return false;
    }
    VIR_DEBUG("mounting tmpfs at '%s'\n", path);
    ret = mount("tmpfs", path, "tmpfs", mountflags, "") == 0;
    if (!ret)
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("failed to mount tmpf: %s"), strerror(errno));
    return ret;
}

static int lxctoolsRunAsync(const char** arglist, pid_t* pid)
{
    pid_t child_pid;
    VIR_DEBUG("about to run %s", arglist[0]);
    child_pid = fork();
    if (child_pid == 0) {
        execvp(arglist[0], (char**)arglist);
        exit(1);
    }
    else if (child_pid < 0) {
        //failed to fork
        return -1;
    } else {
        if (pid != NULL)
            *pid = child_pid;
        return 0;
    }
}

static int lxctoolsWaitPID(pid_t pid)
{
    int return_status;
    VIR_DEBUG("waiting for process %d...", pid);
    waitpid(pid, &return_status, 0);
    VIR_DEBUG("process %d finished with return status %d", pid, WEXITSTATUS(return_status));
    return WEXITSTATUS(return_status);
}

static int lxctoolsRunSync(const char** arglist)
{
    pid_t child;
    if (lxctoolsRunAsync(arglist, &child) < 0)
        return -1;
    else
        return lxctoolsWaitPID(child);
}

pthread_barrier_t start_barrier;

struct thread_data {
    char* path;
    const char* criu_port;
};

static void*
serverThread(void* arg)
{
    struct thread_data *data = (struct thread_data*)arg;
    virCommandPtr criu_cmd = NULL;
    const char* criu_arglist[] = {"criu", "page-server", "--images-dir",
                                  NULL, "--port", data->criu_port,
                                  NULL, NULL,
                                  NULL};
    const char* live_additions[] = { "--prev-images-dir" };
    int i;
    pid_t pid;
    char *predump_path;
    char subdir[3];
    char prev_path[6];
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0)
        return (void*)-1;

    for (i=0; i != LXCTOOLS_LIVE_MIGRATION_ITERATIONS+1; i++) {
        pthread_testcancel();
        sprintf(subdir, "%d", i);
        predump_path = concatPaths(data->path, subdir);

        if (mkdir(predump_path, S_IWUSR | S_IRUSR | S_IRGRP) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("failed to create directory '%s'"),
                           predump_path);
                goto cleanup;
        }
        criu_arglist[3] = predump_path;
        criu_cmd = virCommandNewArgs(criu_arglist);

        if (virCommandRunAsync(criu_cmd, &pid)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("criu page-server returned bad exit code"));
                goto cleanup;
        }

        if (i==0) {
            pthread_barrier_wait(&start_barrier);
        }

        if (lxctoolsWaitPID(pid) != 1) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("criu page-server exited unsuccessfully."));
            virCommandFree(criu_cmd);
            VIR_FREE(predump_path);
            return (void*)-1;
        }

        virCommandFree(criu_cmd);
        VIR_FREE(predump_path);

        sprintf(prev_path, "../%d", i);
        criu_arglist[7] = prev_path;

        if (i==0) {
            criu_arglist[6] = live_additions[0];
        }
    }
    return (void*)-1;
 cleanup:
    virCommandFree(criu_cmd);
    VIR_FREE(predump_path);
    VIR_FREE(data->path);
    return (void*)0;
}

static int
startServerThread(char* path, const char* criu_port, pthread_t **thread)
{
    struct thread_data *data;

    if (VIR_ALLOC(data) < 0)
        return -1;

    if (VIR_ALLOC(*thread) < 0)
        return -1;

    data->path = path;
    data->criu_port = criu_port;
    pthread_barrier_init(&start_barrier, NULL, 2);
    if (pthread_create(*thread, NULL, serverThread, data) != 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("could not start server thread"));
        return -1;
    }

    pthread_barrier_wait(&start_barrier);
    pthread_barrier_destroy(&start_barrier);
    return true;
}

static bool
doPreDumps(const char* dir_path,
          char* prev_path_ret,
          char** dump_path_ret,
          struct lxc_container *cont,
          struct migrate_opts *opts)
{
    int i,j;
    char *predump_path;
    char subdir[5];
    char prev_path[10];
    struct timeval pre_criu, post_criu, criu_runtime;

    for (i=0; i != LXCTOOLS_LIVE_MIGRATION_ITERATIONS; i++) {
        sprintf(subdir, "%d", i);
        predump_path = concatPaths(dir_path, subdir);

        if (mkdir(predump_path, S_IWUSR | S_IRUSR | S_IRGRP) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("failes to create directory '%s'"),
                           predump_path);
                goto cleanup;
        }

	    opts->directory = predump_path;
        for (j=0; j != 10; j++) {
            gettimeofday(&pre_criu, NULL);
            if (cont->migrate(cont, MIGRATE_PRE_DUMP, opts, sizeof(opts))!=0) {
                VIR_DEBUG("migrate failed, try %d/10", j);
	        } else {
                VIR_DEBUG("migrate successfull on try %d/10", j);
                gettimeofday(&post_criu, NULL);
                break;
            }

            if (j==9) {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("criu pre-dump did not start successfully"));
                goto cleanup;
            }
        }
        timersub(&post_criu, &pre_criu, &criu_runtime);
        VIR_DEBUG("Live Migration: Iteration: %d, Runtime:%ld.%06ld", i, (long int)criu_runtime.tv_sec, (long int)criu_runtime.tv_usec);

        /* if migration needed less than 1 second then stop doing pre dumps */
	    if (LXCTOOLS_LIVE_MIGRATION_ENABLE_VARIABLE_STEPS && criu_runtime.tv_sec < 1)
		    break;

        VIR_FREE(predump_path);
	    sprintf(prev_path, "../%d", i);
	    opts->predump_dir = prev_path;
    }
    sprintf(prev_path_ret, "../%d", i-1);
    sprintf(subdir, "%d", i);
    *dump_path_ret = concatPaths(dir_path, subdir);

    if (mkdir(*dump_path_ret, S_IWUSR | S_IRUSR | S_IRGRP) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("failes to create directory '%s'"),
                       *dump_path_ret);
        goto cleanup;
    }
    return true;
 cleanup:
    VIR_FREE(predump_path);
    return false;
}

static bool
doNormalDump(struct lxc_container *cont,
             struct migrate_opts *opts)
{
    int i;
    for (i=0; i != 10; i++) {
        if (cont->migrate(cont, MIGRATE_DUMP, opts, sizeof(opts))!=0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("lxc migrate call failed"));
            break;
        }
    }
    return (i != 9);
}

bool
startCopyProc(const char* pageserver_address,
	          const char* pageserver_port,
              const char* nc_port,
              const char* image_path,
              struct lxc_container* cont,
              bool live)
{
    int copy_ret;
    const char* copy_arglist[] = {"copyclient.sh", image_path, pageserver_address,
                                  nc_port, NULL};
    struct migrate_opts opts;
    opts.directory = (char*)image_path;
    opts.verbose = true;
    opts.stop = true;
    opts.pageserver_address = (char*)pageserver_address;
    opts.pageserver_port = (char*)pageserver_port;
    opts.predump_dir = NULL;
    if (live) {
        char prev_path[5];
        char *dump_path = NULL;
        prev_path[0] = '\0';
        if (!doPreDumps(image_path, prev_path, &dump_path, cont, &opts)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("pre-dump failed."));
            VIR_FREE(dump_path);
            return false;
        }

        opts.directory = dump_path;
        opts.predump_dir = prev_path;
        if (!doNormalDump(cont, &opts)) {
            VIR_FREE(dump_path);
            return false;
        }
        VIR_FREE(dump_path);
    } else {
        if (!doNormalDump(cont, &opts)) {
	        return false;
	    }
    }
    copy_ret = lxctoolsRunSync(copy_arglist);
    VIR_DEBUG("criu client finished successfully, copy client finished: %d", copy_ret);
    return (copy_ret == 0);
}

bool startCopyServer(struct lxctools_migrate_data* md,
                     const char* criu_port,
                     const char* copy_port,
                     const char* path,
                     bool live)
{
    int criu_ret = 0, copy_ret;
    char* pathcpy;
    virCommandPtr criu_cmd;
    const char* criu_arglist[] = {"criu", "page-server", "--images", path,
                                  "--port", criu_port,
                                  NULL};
    const char* copy_arglist[] = {"copysrv.sh", copy_port, path, NULL};

    if (VIR_STRDUP(pathcpy, path) < 0)
        return false;

    if (!live) {
        criu_cmd = virCommandNewArgs(criu_arglist);
        criu_ret = virCommandRunAsync(criu_cmd, &md->criusrv_pid);
        virCommandFree(criu_cmd);
    } else {
        startServerThread(pathcpy, criu_port, &md->server_thread);
    }
    copy_ret = lxctoolsRunAsync(copy_arglist, &md->copysrv_pid);

    VIR_DEBUG("criu server started asynchronously (%d), copy server started asynchronously (%d)", criu_ret, copy_ret);
    return (criu_ret == 0) && (copy_ret == 0);
}


bool
waitForMigrationProcs(struct lxctools_migrate_data* md)
{
    bool ret = true;
    if (md->criusrv_pid > 0 &&
       lxctoolsWaitPID(md->criusrv_pid) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("waiting for criu process failed (pid: %d)"),
                           md->criusrv_pid);
            ret = false;
    } else if (md->criusrv_pid == 0 &&
               md->server_thread != NULL) {
        if (pthread_cancel(*md->server_thread) != 0)
            VIR_DEBUG("thread could not be canceled. It probably already finished.");
    }
    if (md->copysrv_pid > 0 &&
        lxctoolsWaitPID(md->copysrv_pid) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("waiting for copy process failed (pid: %d)"),
                           md->criusrv_pid);
            ret = false;
    }
    return ret;
}


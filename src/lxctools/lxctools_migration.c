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
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

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

static bool portIsOpen(const char* address, int port)
{
    struct sockaddr_in sock_addr;
    struct hostent *server;
    int sock;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	virReportError(VIR_ERR_OPERATION_FAILED, "%s",
		       _("failed to create socket"));
	return false;
    }
    if ((server = gethostbyname(address)) == NULL) {
	virReportError(VIR_ERR_OPERATION_FAILED, "%s",
		       _("host not found"));
        return false;
    }
    bzero((char*) &sock_addr, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    bcopy((char*)server->h_addr, (char*)&sock_addr.sin_addr.s_addr,
          server->h_length);
    sock_addr.sin_port = htons(port);
    if (connect(sock, (struct sockaddr*) &sock_addr, sizeof(sock_addr)) < 0) {
	close(sock);
	return false;
    } else {
	close(sock);
        return true;
    }
}

static
bool waitForPort(const char* address, const char* port, int trys)
{
    int i;
    int iport;
    sscanf(port, "%d", &iport);
    for(i=0; i != trys; i++) {
        if (portIsOpen(address, iport))
            return true;
        usleep(20*1000);
    }
    return false;
}

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

    if (!cont->restore(cont, tmpfs_path, false)) {
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
    VIR_DEBUG("abount to run %s", arglist[0]);
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
    waitpid(pid, &return_status, 0);
    VIR_DEBUG("process %d finished with return status %d", pid, return_status);
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
    virCommandPtr criu_cmd;
    const char* criu_arglist[] = {"criu", "page-server", "--images-dir",
                                  NULL, "--port", data->criu_port,
                                  NULL, NULL, NULL,
                                  NULL};
    const char* live_additions[] = { "--auto-dedup", "--prev-images-dir" };
    int i;
    pid_t pid;
    char *predump_path;
    char subdir[3];
    char prev_path[6];

    for (i=0; i != LXCTOOLS_LIVE_MIGRATION_ITERATIONS+1; i++) {
        sprintf(subdir, "%d", i);
        predump_path = concatPaths(data->path, subdir);

        if (!mkdir(predump_path, S_IWUSR | S_IRUSR | S_IRGRP) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("failed to create directory '%s'"),
                           predump_path);
                goto cleanup;
        }
        criu_arglist[3] = predump_path;
        criu_cmd = virCommandNewArgs(criu_arglist);

        if (virCommandRunAsync(criu_cmd, &pid) != 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("criu page-server returned bad exit code"));
                goto cleanup;
        }

        if (i==0) {
            pthread_barrier_wait(&start_barrier);
        }

        if (lxctoolsWaitPID(pid) < 0)
            return (void*)-1;

        printf("all finished\n");
        virCommandFree(criu_cmd);
        VIR_FREE(predump_path);

        sprintf(prev_path, "../%d", i);
        criu_arglist[8] = prev_path;

        if (i==0) {
            criu_arglist[6] = live_additions[0];
            criu_arglist[7] = live_additions[1];
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
startServerThread(char* path, const char* criu_port)
{
    struct thread_data *data;
    pthread_t thread;

    if (VIR_ALLOC(data) < 0)
        return -1;

    data->path = path;
    data->criu_port = criu_port;
    pthread_barrier_init(&start_barrier, NULL, 2);
    if (pthread_create(&thread, NULL, serverThread, data) != 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("could not start server thread"));
        return -1;
    }

    pthread_barrier_wait(&start_barrier);
    pthread_barrier_destroy(&start_barrier);
    return true;
}

static bool
doPreDump(const char* criu_port,
          const char* path,
          const char* pid,
          const char* dconnuri,
          char* prev_path_ret,
          char** dump_path_ret ATTRIBUTE_UNUSED)
{
    virCommandPtr criu_cmd;
    const char* criu_arglist[] = {"criu", "pre-dump", "--tcp-established",
                                  "--file-locks", "--link-remap",
                                  "--force-irmap", "--manage-cgroups",
                                  "--ext-mount-map", "auto",
                                  "--enable-external-sharing",
                                  "--enable-external-masters",
                                  "--enable-fs", "hugetlbfs", "--tree",
                                  pid, "--images-dir", NULL,
                                  "--page-server", "--address", dconnuri,
                                  "--port", criu_port,
                                  NULL, NULL,
                                  NULL, NULL};
    const char* live_additions[] = { "--auto-dedup", "--prev-images-dir" };
    int i;
    char *predump_path;
    char subdir[3];
    char prev_path[6];

    for (i=0; i != LXCTOOLS_LIVE_MIGRATION_ITERATIONS; i++) {
        sprintf(subdir, "%d", i);
        predump_path = concatPaths(path, subdir);

        if (!mkdir(predump_path, S_IWUSR | S_IRUSR | S_IRGRP) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("failes to create directory '%s'"),
                           predump_path);
                goto cleanup;
        }
        criu_arglist[16] = predump_path;
        criu_cmd = virCommandNewArgs(criu_arglist);

        if (!waitForPort(dconnuri, criu_port, 10)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("waiting for open port on destination failed."));
            return false;
        }
        if (virCommandRun(criu_cmd, NULL) != 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("criu pre-dump returned bad exit code"));
                goto cleanup;
        }
        virCommandFree(criu_cmd);
        VIR_FREE(predump_path);

        sprintf(prev_path, "../%d", i);
        criu_arglist[24] = prev_path;

        if (i==0) {
            criu_arglist[22] = live_additions[0];
            criu_arglist[23] = live_additions[1];
        }
    }
    sprintf(prev_path_ret, "../%d", LXCTOOLS_LIVE_MIGRATION_ITERATIONS-1);
    sprintf(subdir, "%d", LXCTOOLS_LIVE_MIGRATION_ITERATIONS);
    *dump_path_ret = concatPaths(path, subdir);

    if (!mkdir(*dump_path_ret, S_IWUSR | S_IRUSR | S_IRGRP) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("failes to create directory '%s'"),
                       *dump_path_ret);
            goto cleanup;
    }
    return true;
 cleanup:
    virCommandFree(criu_cmd);
    VIR_FREE(predump_path);
    return false;
}

static bool
doNormalDump(const char* criu_port,
             const char* path,
             const char* pid,
             const char* dconnuri,
             const char* prev_path)
{
    int criu_ret;
    virCommandPtr criu_cmd;
    const char* criu_arglist[] = {"criu", "dump", "--tcp-established",
                                  "--file-locks", "--link-remap",
                                  "--force-irmap", "--manage-cgroups",
                                  "--ext-mount-map", "auto",
                                  "--enable-external-sharing",
                                  "--enable-external-masters",
                                  "--enable-fs", "hugetlbfs", "--tree",
                                  pid, "--images-dir", path,
                                  "--page-server", "--address", dconnuri,
                                  "--port", criu_port,
                                  "--prev-images-dir", prev_path,
                                  "--auto-dedup", NULL};
    if (prev_path == NULL)
        criu_arglist[22] = NULL;

    criu_cmd = virCommandNewArgs(criu_arglist);
    if (!waitForPort(dconnuri, criu_port, 10)) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("waiting for open port on destination failed."));
        return false;
    }
    criu_ret = virCommandRun(criu_cmd, NULL);
    virCommandFree(criu_cmd);

    return (criu_ret == 0);
}

bool
startCopyProc(struct lxctools_migrate_data* md ATTRIBUTE_UNUSED,
              const char* criu_port,
              const char* copy_port,
              const char* path,
              pid_t pid,
              const char* dconnuri,
              bool live)
{
    char pid_str[15];
    int copy_ret;
    const char* copy_arglist[] = {"copyclient.sh", path, dconnuri,
                                  copy_port, NULL};
    sprintf(pid_str, "%d", pid);
    if (live) {
        char prev_path[5];
        char *dump_path = NULL;
        prev_path[0] = '\0';
        if (!doPreDump(criu_port, path, pid_str, dconnuri, prev_path, &dump_path)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("pre-dump failed."));
            VIR_FREE(dump_path);
            return false;
        }

        if (!doNormalDump(criu_port, dump_path, pid_str, dconnuri, prev_path)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("final dump failed."));
            VIR_FREE(dump_path);
            return false;
        }
        VIR_FREE(dump_path);
    } else {
        if (!doNormalDump(criu_port, path, pid_str, dconnuri, NULL)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                          _("normal dump failed."));
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
        criu_arglist[6] = NULL;
        criu_cmd = virCommandNewArgs(criu_arglist);
        criu_ret = virCommandRunAsync(criu_cmd, &md->criusrv_pid);
        virCommandFree(criu_cmd);
    } else {
        startServerThread(pathcpy, criu_port);
    }
    copy_ret = lxctoolsRunAsync(copy_arglist, &md->copysrv_pid);

    VIR_DEBUG("criu server started asynchronously (%d), copy server started asynchronously (%d)", criu_ret, copy_ret);
    return (criu_ret == 0) && (copy_ret == 0);
}


bool
waitForMigrationProcs(struct lxctools_migrate_data* md)
{
    bool ret = true;
    void* retval = 0;
    if (md->criusrv_pid > 0 &&
       lxctoolsWaitPID(md->criusrv_pid) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("waiting for criu process failed (pid: %d)"),
                           md->criusrv_pid);
            ret = false;
    } else if (md->criusrv_pid == 0 &&
               md->server_thread != NULL) {
        if (pthread_join(*md->server_thread, &retval) != 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                          _("failed to join server thread"));
            ret = false;
        }
        ret =  (*((int*)retval) == 0);
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


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
#include "lxctools_filecpy_server.h"
#include "lxctools_filecpy_client.h"

#define VIR_FROM_THIS VIR_FROM_LXCTOOLS

VIR_LOG_INIT("lxctools.lxctools_migration");


int restoreContainer(struct lxc_container *cont, bool live ATTRIBUTE_UNUSED, int migration_iterations)
{
    struct migrate_opts opts = {0};
    char *tmpfs_path = NULL;
    char tmpfs_suffix[16] = "migrate_tmpfs";
    int ret = -1;

    //if (live)
    sprintf(tmpfs_suffix, "migrate_tmpfs/%d", migration_iterations-1);

    if ((tmpfs_path = concatPaths(cont->get_config_path(cont),
                                  tmpfs_suffix)) == NULL)
        goto cleanup;

    opts.directory = tmpfs_path;
    opts.verbose = true;
    opts.stop = false;
    opts.pageserver_address = NULL;
    opts.pageserver_port = NULL;
    opts.predump_dir = NULL;

    if (cont->migrate(cont, MIGRATE_RESTORE, &opts, sizeof(opts))!=0) {
        VIR_ERROR("%s","lxc api call failed. check lxc log for more information");
        goto cleanup;
    }


    if (!cont->is_running(cont)) {
        VIR_ERROR("something went wrong while restoring");
        goto cleanup;
    }
    ret = 0;
 cleanup:
    VIR_FREE(tmpfs_path);
    return ret;
}

int createTmpfs(const char* path)
{
    int ret;
    unsigned long mountflags = MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID;
    if (!virFileExists(path)) {
        VIR_ERROR("path '%s' does not exist", path);
        return -1;
    }

    if (!virFileIsDir(path)) {
        VIR_ERROR("path '%s' does not point to a directory", path);
        return -1;
    }
    VIR_DEBUG("mounting tmpfs at '%s'\n", path);
    if ((ret = mount("tmpfs", path, "tmpfs", mountflags, "")) != 0)
        VIR_ERROR("failed to mount tmpf: %s", strerror(errno));
    return ret;
}

/*static int lxctoolsRunAsync(const char** arglist, pid_t* pid)
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
        VIR_DEBUG("started process with pid %d", child_pid);
        if (pid != NULL)
            *pid = child_pid;
        return 0;
    }
}*/

static int lxctoolsWaitPID(pid_t pid)
{
    int return_status;
    VIR_DEBUG("waiting for process %d...", pid);
    waitpid(pid, &return_status, 0);
    VIR_DEBUG("process %d finished with return status %d", pid, WEXITSTATUS(return_status));
    return WEXITSTATUS(return_status);
}

/*static int lxctoolsRunSync(const char** arglist)
{
    pid_t child;
    if (lxctoolsRunAsync(arglist, &child) < 0)
        return -1;
    else
        return lxctoolsWaitPID(child);
}
*/
pthread_barrier_t start_barrier;

struct thread_data {
    char* path;
    const char* criu_port;
    const char* cpy_port;
};

static void*
serverThread(void* arg)
{
    struct thread_data *data = (struct thread_data*)arg;

    virCommandPtr criu_cmd = NULL;
    const char* criu_arglist[] = {"criu", "page-server", "--images-dir", NULL /* set to predump_path */,
                                  "--port", data->criu_port,
                                  NULL /* if live -> --prev-images-dir */, NULL /* if live -> prev-path*/,
                                  NULL};
    const char* live_additions[] = { "--prev-images-dir" };
    int i;
    pid_t pid;
    char *predump_path = NULL;
    char subdir[3];
    char prev_path[6];
    int filecpy_socket = -1;
    int peersocket = -1;
    statustype_t status;
    int* ret;

    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0) {
        VIR_DEBUG("Failed setting cancel state to enabled.\n");
        return (void*)-1;
    }

    VIR_DEBUG("Starting filecopy server at port '%s'\n", data->cpy_port);
    if ((filecpy_socket = server_start(data->cpy_port)) < 0) {
        VIR_DEBUG("ERROR:  failed to start filecopy server at port '%s'\n",
               data->cpy_port);
        goto cleanup;
    }
    pthread_barrier_wait(&start_barrier);

    VIR_DEBUG("Connecting to client.\n");
    if ((peersocket = server_connect_block(filecpy_socket)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("failed to connect to client"));
        goto cleanup;
    }

    for (i=0; i != LXCTOOLS_LIVE_MIGRATION_ITERATIONS+1; i++) {
        VIR_DEBUG("Iteration '%d'\n", i);
        pthread_testcancel();
        status = server_receive_status_noblock(peersocket);
        if (status == STATUS_ERR) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("failed to receive status"));
            goto cleanup;
        } else if (status == STATUS_END) {
            VIR_DEBUG("Received STATUS_END aftere %d iterations.", i);
            break;
        }

        sprintf(subdir, "%d", i);
        predump_path = concatPaths(data->path, subdir);

        VIR_DEBUG("Creating directory '%s'\n", predump_path);
        if (mkdir(predump_path, S_IWUSR | S_IRUSR | S_IRGRP) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("failed to create directory '%s'"),
                           predump_path);
            goto cleanup;
        }
        criu_arglist[3] = predump_path;

        VIR_DEBUG("Running criu page-server.\n");
        criu_cmd = virCommandNewArgs(criu_arglist);
        if (virCommandRunAsync(criu_cmd, &pid)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("criu page-server returned bad exit code"));
            goto cleanup;
        }
        if (server_send_status(peersocket, STATUS_RDY) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("sending STATUS_RDY failed"));
            goto cleanup;
        }
        VIR_DEBUG("######### Wait for criu page-server###############");
        if (lxctoolsWaitPID(pid) != 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("criu page-server exited unsuccessfully."));
            virCommandFree(criu_cmd);
            return (void*)-1;
        }

        // Set --prev-images-dir <prev_path>
        if (i==0)
            criu_arglist[6] = live_additions[0];
        sprintf(prev_path, "../%d", i);
        criu_arglist[7] = prev_path;
    }
    VIR_DEBUG("######### Server receive files###############");
    if (server_receive_files(peersocket, data->path) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "failed to receive files to path '%s'.",
                       data->path);
        goto cleanup;
    }
    server_close(peersocket);
    VIR_FREE(data->path);
    virCommandFree(criu_cmd);
    VIR_FREE(data);
    if (VIR_ALLOC(ret) < 0) goto cleanup;
    *ret = i;
    VIR_DEBUG("thread ended");
    return (void*)(ret);
 cleanup:
    printf("performing thread cleanup\n");
    server_close(peersocket);
    virCommandFree(criu_cmd);
    VIR_FREE(data->path);
    VIR_FREE(data);
    return (void*)-1;
}

static int
startServerThread(char* path, const char* criu_port, const char* cpy_port, pthread_t **thread)
{
    struct thread_data *data;

    if (VIR_ALLOC(data) < 0)
        return -1;

    if (VIR_ALLOC(*thread) < 0)
        return -1;

    data->path = path;
    data->criu_port = criu_port;
    data->cpy_port = cpy_port;
    pthread_barrier_init(&start_barrier, NULL, 2);
    if (pthread_create(*thread, NULL, serverThread, data) != 0) {
        VIR_ERROR("could not start server thread");
        return -1;
    }

    pthread_barrier_wait(&start_barrier);
    pthread_barrier_destroy(&start_barrier);
    return 0;
}

static int
doPreDumps(const char* dir_path,
          char* prev_path_ret,
          char** dump_path_ret,
          struct lxc_container *cont,
          struct migrate_opts *opts,
          int filecpy_socket)
{
    int i;
    char *predump_path;
    char subdir[5];
    char prev_path[10];
    struct timeval pre_criu, post_criu, criu_runtime;
    statustype_t status;

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
        status = client_receive_status(filecpy_socket);
        if (status != STATUS_RDY) {
            virReportError(VIR_ERR_OPERATION_FAILED, "received status %d instead of STATUS_RDY.", status);
            goto cleanup;
        }
        gettimeofday(&pre_criu, NULL);
        if (cont->migrate(cont, MIGRATE_PRE_DUMP, opts, sizeof(*opts))!=0) {
            VIR_DEBUG("migrate failed");
            goto cleanup;
        } else {
            VIR_DEBUG("migrate successfull");
            gettimeofday(&post_criu, NULL);
        }

        timersub(&post_criu, &pre_criu, &criu_runtime);
        VIR_DEBUG("Live Migration: Iteration: %d, Runtime:%ld.%06ld", i, (long int)criu_runtime.tv_sec, (long int)criu_runtime.tv_usec);
#ifdef LXCTOOLS_EVALUATION
        printf("pre-dump %d: %ld.%06ld ", i, (long int)criu_runtime.tv_sec, (long int)criu_runtime.tv_usec);
        FILE *time_file = fopen("/tmp/lxctoolseval", "a+");
        fprintf(time_file, "%ld.%06ld ", (long int)criu_runtime.tv_sec, (long int)criu_runtime.tv_usec);
#endif

        /* if migration needed less than 1 second then stop doing pre dumps */
        if (LXCTOOLS_LIVE_MIGRATION_ENABLE_VARIABLE_STEPS && criu_runtime.tv_sec < 1) {
            i++;
            break;
        }

        VIR_FREE(predump_path);
        sprintf(prev_path, "../%d", i);
        opts->predump_dir = prev_path;
    }
    sprintf(prev_path_ret, "../%d", i-1);
    sprintf(subdir, "%d", i);
    *dump_path_ret = concatPaths(dir_path, subdir);

    if (mkdir(*dump_path_ret, S_IWUSR | S_IRUSR | S_IRGRP) < 0) {
        VIR_DEBUG("migrate failed");
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("failes to create directory '%s'"),
                       *dump_path_ret);
        goto cleanup;
    }
    return 0;
 cleanup:
    VIR_FREE(predump_path);
    return -1;
}

static int
doNormalDump(struct lxc_container *cont,
             struct migrate_opts *opts,
             int filecpy_socket)
{
    struct timeval pre_dump, post_dump, dump_runtime;
    statustype_t status;
    VIR_DEBUG("performing (final) normal migration...");
    opts->stop = true;

    status = client_receive_status(filecpy_socket);
    if (status != STATUS_RDY) {
        VIR_ERROR("received status %d instead of STATUS_RDY during normal dump.", status);
        return -1;
    }
    if (server_send_status(filecpy_socket, STATUS_END) < 0) {
        VIR_ERROR("Failed sending STATUS_END to filecpy_socket.");
        return -1;
    }

    gettimeofday(&pre_dump, NULL);
    VIR_DEBUG("Calling LXC dump...");
    VIR_DEBUG("pageserver_address %s", opts->pageserver_address);
    VIR_DEBUG("pageserver_port %s", opts->pageserver_port);
    if (opts->action_script)
        VIR_DEBUG("action_script %s", opts->action_script);
    if (cont->migrate(cont, MIGRATE_DUMP, opts, sizeof(*opts))!=0) {
        VIR_DEBUG("migrate failed");
    } else {
        VIR_DEBUG("LXC dump successfull");
        gettimeofday(&post_dump, NULL);
        timersub(&post_dump, &pre_dump, &dump_runtime);
        VIR_DEBUG("Normal Migration: Runtime:%ld.%06ld", (long int)dump_runtime.tv_sec, (long int)dump_runtime.tv_usec);
#ifdef LXCTOOLS_EVALUATION
printf("dump: %ld.%06ld ", (long int)dump_runtime.tv_sec, (long int)dump_runtime.tv_usec);
FILE *time_file = fopen("/tmp/lxctoolseval", "a+");
fprintf(time_file, "%ld.%06ld ", (long int)dump_runtime.tv_sec, (long int)dump_runtime.tv_usec);
#endif


        return 0;
     }
     virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                   _("lxc migrate call failed"));
    return -1;
}

int
startCopyProc(const char* pageserver_address,
              const char* pageserver_port,
              const char* nc_port,
              const char* image_path,
              struct lxc_container* cont,
              bool live)
{
    int ret = -1;
    int filecpy_socket = -1;
    struct migrate_opts opts = {0};
    opts.directory = (char*)image_path;
    opts.verbose = true;
    opts.stop = false;
    opts.pageserver_address = (char*)pageserver_address;
    opts.pageserver_port = (char*)pageserver_port;
    VIR_DEBUG("pageserver_address %s", opts.pageserver_address);
    VIR_DEBUG("pageserver_port %s", opts.pageserver_port);
    opts.predump_dir = NULL;

    if ((filecpy_socket = client_connect(pageserver_address, nc_port)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, _("could not connect to filecpy server at %s:%s"), pageserver_address, nc_port);
        return -1;
    }
    VIR_DEBUG("starting migration...");
    if (live) {
        char prev_path[5];
        char *dump_path = NULL;
        prev_path[0] = '\0';
        VIR_DEBUG("doing predumps...");
        if (doPreDumps(image_path, prev_path, &dump_path, cont, &opts, filecpy_socket) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("pre-dump failed."));
            VIR_FREE(dump_path);
            goto err;
        }
        VIR_DEBUG("finished predumps. starting normal dump...");
        opts.directory = dump_path;
        opts.predump_dir = prev_path;
        if (doNormalDump(cont, &opts, filecpy_socket) < 0) {
            VIR_FREE(dump_path);
            goto err;
        }
        VIR_DEBUG("finished normal dump");
        VIR_FREE(dump_path);
    } else {
        char *subdir = NULL;
        if (asprintf(&subdir, "%s/0", opts.directory) < 0)
            goto err;
        opts.directory = subdir;
        VIR_DEBUG("doing non live dump");
        if (doNormalDump(cont, &opts, filecpy_socket) < 0) {
            free(subdir);
            goto err;
        }
        free(subdir);
    }
    VIR_DEBUG("sending dir");
    if (client_senddir(image_path) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "an error occured during senddir from path %s", image_path);
        goto err;
    }
    VIR_DEBUG("criu client finished successfully, copy client finished successfulley");
    ret = 0;
 err:
   // client_close(filecpy_socket);
    return ret;
}

int startCopyServer(struct lxctools_migrate_data* md,
                     const char* criu_port,
                     const char* copy_port,
                     const char* path,
                     bool live ATTRIBUTE_UNUSED)
{
    char* pathcpy = NULL;
    if (VIR_STRDUP(pathcpy, path) < 0)
        return -1;
    int ret = startServerThread(pathcpy, criu_port, copy_port, &md->server_thread);
    return ret;
}


/* return number of migration iterations performed or -1 on error */
int
waitForMigrationProcs(struct lxctools_migrate_data* md)
{
    int ret = -1;
    void* thread_res;
    int error_num;
    if (md->criusrv_pid > 0 &&
       lxctoolsWaitPID(md->criusrv_pid) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("waiting for criu process failed (pid: %d)"),
                           md->criusrv_pid);
            goto error;
    } else if (md->criusrv_pid == 0 &&
               md->server_thread != NULL) {
        struct timespec timeout;
        if (clock_gettime(CLOCK_REALTIME, &timeout) == -1) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("could not get current time"));
            goto error;
        }
        timeout.tv_sec += 5;
        if ((error_num= pthread_timedjoin_np(*md->server_thread, &thread_res, &timeout)) != 0) {
            if (error_num != EBUSY && error_num != ETIMEDOUT) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("thread join failed: error %d"), error_num);
                goto error;
            } else {
                if (pthread_cancel(*md->server_thread) != 0)
                    VIR_DEBUG("thread could not be canceled. It probably already finished.");
                if (pthread_join(*md->server_thread, &thread_res) != 0) {
                    virReportError(VIR_ERR_OPERATION_FAILED,
                                   "%s", _("thread did not join after cancellation"));
                    VIR_FREE(md->server_thread);
                    md->server_thread = NULL;
                    goto error;
                } else if (thread_res == PTHREAD_CANCELED) {
                    VIR_DEBUG("thread was canceled");
                    VIR_FREE(md->server_thread);
                    md->server_thread = NULL;
                    goto error;
                }
            }/*
        if (pthread_join(*md->server_thread, &thread_res) != 0) {
            printf("error\n");
            goto error;*/
        } else {
            ret = *(int*)thread_res;
            VIR_FREE(thread_res);
            VIR_FREE(md->server_thread);
            md->server_thread = NULL;
            return ret;
        }
    }
  /*  if (md->copysrv_pid > 0 &&
        lxctoolsWaitPID(md->copysrv_pid) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("waiting for copy process failed (pid: %d)"),
                           md->criusrv_pid);
            goto error;
    }*/
 error:
    return ret;
}


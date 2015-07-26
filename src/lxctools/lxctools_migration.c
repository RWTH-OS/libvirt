#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "viralloc.h"
#include "vircommand.h"
#include "virfile.h"
#include "lxctools_conf.h"
#include "virlog.h"
#include "lxctools_migration.h"

#define VIR_FROM_THIS VIR_FROM_LXCTOOLS

VIR_LOG_INIT("lxctools.lxctools_migration");

int restoreContainer(struct lxc_container *cont)
{
    char *tmpfs_path = NULL;
    int ret = -1;
    if ((tmpfs_path = concatPaths(cont->get_config_path(cont),
                                  "migrate_tmpfs")) == NULL)
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
    const char* path;
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
    return (void*)0;
}

static int
startServerThread(const char* path, const char* criu_port)
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

/* TODO:
 * first pre-dump w/o --prev-images-dir
 * following pre-dumps  and final dump with --prev-images-dir
 * create subdir for each dump
 * on server side create dump subdirs as well
 */
static bool
doPreDump(const char* criu_port,
          const char* path,
          const char* pid,
          const char* dconnuri,
          char* prev_path_ret)
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

        if (virCommandRun(criu_cmd, NULL) != 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("criu pre-dump returned bad exit code"));
                goto cleanup;
        }
        printf("all finished\n");
        virCommandFree(criu_cmd);
        VIR_FREE(predump_path);

        sprintf(prev_path, "../%d", i);
        criu_arglist[24] = prev_path;

        if (i==0) {
            criu_arglist[22] = live_additions[0];
            criu_arglist[23] = live_additions[1];
        }
    }
    sprintf(prev_path_ret, "%d", LXCTOOLS_LIVE_MIGRATION_ITERATIONS-1);
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
    char prev_path[3];
    int copy_ret;
    const char* copy_arglist[] = {"copyclient.sh", path, dconnuri,
                                  copy_port, NULL};
    sprintf(pid_str, "%d", pid);
    prev_path[0] = '\0';
    if (live) {
        if (!doPreDump(criu_port, path, pid_str, dconnuri, prev_path)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("pre-dump failed."));
            return false;
        }
        if (!doNormalDump(criu_port, path, pid_str, dconnuri, prev_path)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("final dump failed."));
            return false;
        }
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
    virCommandPtr criu_cmd;
    const char* criu_arglist[] = {"criu", "page-server", "--images", path,
                                  "--port", criu_port,
                                  NULL};
    const char* copy_arglist[] = {"copysrv.sh", copy_port, path, NULL};

    if (!live) {
        criu_arglist[6] = NULL;
        criu_cmd = virCommandNewArgs(criu_arglist);
        criu_ret = virCommandRunAsync(criu_cmd, &md->criusrv_pid);
        virCommandFree(criu_cmd);
    } else {
        startServerThread(path, criu_port);
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


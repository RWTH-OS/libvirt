/*
 * openvz_conf.c: config functions for managing OpenVZ VEs
 *
 * Copyright (C) 2010-2012, 2014 Red Hat, Inc.
 * Copyright (C) 2006, 2007 Binary Karma
 * Copyright (C) 2006 Shuveb Hussain
 * Copyright (C) 2007 Anoop Joe Cyriac
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
 * Shuveb Hussain <shuveb@binarykarma.com>
 * Anoop Joe Cyriac <anoop@binarykarma.com>
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mount.h>

#include "viralloc.h"
#include "vircommand.h"
#include "virstring.h"
#include "virfile.h"
#include "lxctools_conf.h"

#define VIR_FROM_THIS VIR_FROM_LXCTOOLS

/*
static void printUUID(const unsigned char *uuid)
{
    char str[VIR_UUID_STRING_BUFLEN];
    virUUIDFormat(uuid, str);
    printf("UUID: %s\n", str);

}*/
/*
 * FIXME: DEBUG THIS!!!
 */
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
    printf("mounting tmpfs at '%s'\n", path);
    ret = mount("tmpfs", path, "tmpfs", mountflags, "") == 0;
    printf("errno: %d\n", errno);
    return ret;
}

char* getContainerNameFromPath(const char* path)
{
    int pathlen;
    int i = 0;
    char* ret = NULL;
    if (path == NULL)
        return NULL;

    pathlen = strlen(path);

    if (path[pathlen-1] == '/') {
        pathlen--;
    }
    i = pathlen - 1;
    while(i > 0 && path[i] != '/') {
        i--;
    }

    if (VIR_ALLOC_N(ret, pathlen-i) < 0) {
        return NULL;
    }

    return virStrncpy(ret, path+i+1, pathlen-i-1, pathlen-i);
}

char* concatPaths(const char* path1, const char* path2)
{
    char* ret;
    int path1len, path2len;
    int retlen;
    if (path1 == NULL)
        path1len = 0;
    else
        path1len = strlen(path1);

    if (path2 == NULL)
        path2len = 0;
    else
        path2len = strlen(path2);

    if (path1[path1len-1] != '/')
        retlen = path1len+path2len+1;
    else
        retlen = path1len+path2len;

    if (VIR_ALLOC_N(ret, retlen) < 0) {
        return NULL;
    }

    if (path1[path1len-1] != '/')
        sprintf(ret, "%s/%s", path1, path2);
    else
        sprintf(ret, "%s%s", path1, path2);

    return ret;
}

bool criuExists(void)
{
    const char* prog[] = {"which", "criu", NULL};
    return (virRun(prog, NULL) == 0);
}

virDomainState lxcState2virState(const char* state)
{
    if (STREQ(state, "STOPPED"))
        return VIR_DOMAIN_SHUTOFF;
    if (STREQ(state, "STARTING") ||
        STREQ(state, "RUNNING"))
        return VIR_DOMAIN_RUNNING;
    if (STREQ(state, "ABORTING") ||
        STREQ(state, "STOPPING"))
        return VIR_DOMAIN_SHUTDOWN;
    if (STREQ(state, "FREEZING") ||
        STREQ(state, "FROZEN") ||
        STREQ(state, "THAWED"))
        return VIR_DOMAIN_PAUSED;

    return VIR_DOMAIN_NOSTATE;
}

void lxctoolsFreeDriver(struct lxctools_driver* driver)
{
    if(!driver)
        return;
    free((void*)driver->path);
    virObjectUnref(driver->domains);
    VIR_FREE(driver);
}

static void container_cleaner(void* ptr) {
    struct lxc_container* cont;
    if(ptr) {
        cont = ptr;
        VIR_FREE(cont);
    }
}

unsigned long convertMemorySize(char* memory_str, unsigned int strlen) {
    unsigned long ret;
    switch(memory_str[strlen-1]) {
        case 'g':
        case 'G':
            ret = 1024*1024;
            memory_str[strlen-1] = '\0';
            ret *= strtol(memory_str, NULL, 10);
            return ret;
        case 'm':
        case 'M':
            ret = 1024;
            memory_str[strlen-1] = '\0';
            ret *= strtol(memory_str, NULL, 10);
            return ret;
        case 'k':
        case 'K':
            memory_str[strlen-1] = '\0';
            ret = strtol(memory_str, NULL, 10);
            return ret;
        default:
            ret = strtol(memory_str, NULL, 10);
            return ret/1024;
        }
}

unsigned long getHostMemory(virConnectPtr conn)
{
    virNodeInfoPtr info = NULL;
    unsigned int ret = 0;
    if (VIR_ALLOC(info) < 0)
        goto cleanup;

    if (virNodeGetInfo(conn, info) < 0)
        goto cleanup;

    ret = info->memory;
cleanup:
    VIR_FREE(info);
    return ret;
}

unsigned int getNumOfHostCPUs(virConnectPtr conn)
{
    virNodeInfoPtr info = NULL;
    unsigned int ret = 0;
    if (VIR_ALLOC(info) < 0)
        goto cleanup;

    if (virNodeGetInfo(conn, info) < 0)
        goto cleanup;

    ret = info->cpus;
cleanup:
    VIR_FREE(info);
    return ret;
}

int lxctoolsLoadDomains(struct lxctools_driver *driver)
{
    int i,flags;
    virDomainObjPtr dom = NULL;
    virDomainDefPtr def = NULL;
    int cret_len;
    struct lxc_container** cret;
    char** names;
    virDomainXMLOptionPtr xmlopt;
    if ((cret_len = list_all_containers(driver->path, &names, &cret)) < 0)
        goto cleanup;

    for (i=0; i < cret_len; ++i) {
        //cret[i]->set_config_item(cret[i],"lxc.loglevel", "1");
        if (!(def = virDomainDefNew()))
            goto cleanup;

        def->virtType = VIR_DOMAIN_VIRT_LXCTOOLS;
        if (!cret[i]->is_running(cret[i]))
            def->id = -1;
        else
            def->id = cret[i]->init_pid(cret[i]);

        if(virUUIDGenerate(def->uuid) < 0) {
           goto cleanup;
        }

        def->name = names[i];

        //printUUID(def->uuid);

        flags = VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE;
        if (def->id != -1)
           flags |= VIR_DOMAIN_OBJ_LIST_ADD_LIVE;

        if (!(xmlopt = virDomainXMLOptionNew(NULL, NULL, NULL)))
            goto cleanup;

        if (!(dom = virDomainObjListAdd(driver->domains,
                                        def,
                                        xmlopt,
                                        flags,
                                        NULL)))
            goto cleanup;
        if (!cret[i]->is_running(cret[i])) {
            virDomainObjSetState(dom, VIR_DOMAIN_SHUTOFF,
                                 VIR_DOMAIN_SHUTOFF_UNKNOWN);
            dom->pid = -1;
        } else {
            virDomainObjSetState(dom, VIR_DOMAIN_RUNNING,
                                 VIR_DOMAIN_RUNNING_UNKNOWN);
            dom->pid = cret[i]->init_pid(cret[i]);
        }
        dom->persistent = 1;
        dom->privateData = cret[i];
        dom->privateDataFreeFunc = &container_cleaner;
        virObjectUnlock(dom);
        dom = NULL;
        def = NULL;
    }
    return 0;

cleanup:
    VIR_FREE(cret);
    virObjectUnref(dom);
    virDomainDefFree(def);
    return -1;
}

#include <sys/wait.h>

static int lxctoolsRunAsync(const char** arglist, pid_t* pid)
{
    pid_t child_pid;
    child_pid = fork();
    if (child_pid == 0) {
        execvp(arglist[0], (char**)arglist);
        exit(1);
    }
    else if (child_pid < 0) {
        //printf("failed to fork\n");
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
/*
static int run_copy_proc(const char* path, const char* dconnuri, const char* copy_port)
{
    const char* copy_arglist[] = {"copyclient.sh", path,
                                  dconnuri, copy_port, NULL};
    pid_t child_pid;
    child_pid = fork();
    if (child_pid == 0) {
        execvp(copy_arglist[0], (char**)copy_arglist);
        exit(1);
    }
    else if (child_pid < 0) {
        printf("failed to fork\n");
        return -1;
    } else {
        int return_status;
        waitpid(child_pid, &return_status, 0);
        printf("return_status: %d", WEXITSTATUS(return_status));
        return WEXITSTATUS(return_status);
    }
}

static int run_copy_srv(const char* copy_port, const char* path)
{
    const char* copy_arglist[] = { "copysrv.sh", copy_port, path, NULL };
    pid_t child_pid;
    child_pid = fork();
    if (child_pid == 0) {
        execvp(copy_arglist[0], (char*const*)copy_arglist);
        exit(1);
    }
    else if (child_pid < 0) {
        printf("FAIL\n");
        return -1;
    } else {
        return child_pid;
    }
}*/

bool
startCopyProc(struct lxctools_migrate_data* md ATTRIBUTE_UNUSED, const char* criu_port, const char* copy_port, const char* path, pid_t pid, const char* dconnuri)
{
    char pid_str[15];
    int copy_ret, criu_ret;
    virCommandPtr criu_cmd;
    const char* criu_arglist[] = {"criu", "dump", "--tcp-established",
                              "--file-locks", "--link-remap",
                              "--force-irmap", "--manage-cgroups",
                              "--ext-mount-map", "auto",
                              "--enable-external-sharing",
                              "--enable-external-masters",
                              "--enable-fs", "hugetlbfs", "--tree",
                              NULL, "--images-dir", path,
                              "--page-server", "--address", dconnuri,
                              "--port", criu_port,
                              "--leave-stopped", NULL};
    const char* copy_arglist[] = {"copyclient.sh", path,
                                  dconnuri, copy_port, NULL};
    sprintf(pid_str, "%d", pid);
    criu_arglist[14] = pid_str;

    criu_cmd = virCommandNewArgs(criu_arglist);
    criu_ret = virCommandRun(criu_cmd, NULL);
    copy_ret = lxctoolsRunSync(copy_arglist);

    virCommandFree(criu_cmd);
    printf("criu: %d, copy: %d\n", criu_ret, copy_ret);
    return (criu_ret == 0) && (copy_ret == 0);
}

bool
startCopyServer(struct lxctools_migrate_data* md, const char* criu_port, const char* copy_port, const char* path)
{
    int criu_ret, copy_ret = 0;
    virCommandPtr criu_cmd;
    const char* criu_arglist[] = {"criu", "page-server", "--images", path,
                              "--port", criu_port, NULL};
    const char* copy_arglist[] = { "copysrv.sh", copy_port, path, NULL };

    criu_cmd = virCommandNewArgs(criu_arglist);
    criu_ret = virCommandRunAsync(criu_cmd, &md->criusrv_pid);
    copy_ret = lxctoolsRunAsync(copy_arglist, &md->copysrv_pid);
    printf("copysrv ret:%d\n", copy_ret);
    virCommandFree(criu_cmd);
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
    }
    if (md->copysrv_pid > 0 &&
        lxctoolsWaitPID(md->copysrv_pid) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("waiting for copy process failed (pid: %d)"),
                           md->criusrv_pid);
            ret = false;
    }
    /*if (md->criusrv_pid > 0 &&
        virProcessWait(md->criusrv_pid, NULL, false) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("waiting for criu process failed (pid: %d)"),
                       md->criusrv_pid);
        ret = false;
    }
    if (md->copysrv_pid > 0 &&
        virProcessWait(md->copysrv_pid, NULL, false) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("waiting for copy process failed (pid: %d)"),
                       md->copysrv_pid);
        ret = false;
    }*/
    return ret;
}

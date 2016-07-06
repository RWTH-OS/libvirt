/*
 * lxctools_conf.c: config functions for lxctools
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

/*TODO: implement runtime config manipulation */
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
#include "virlog.h"
#include "nodeinfo.h"


#define VIR_FROM_THIS VIR_FROM_LXCTOOLS

VIR_LOG_INIT("lxctools.lxctools_conf");

virCapsPtr lxctoolsCapabilitiesInit(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   true, true)) == NULL)
        goto no_memory;

    if (nodeCapsInitNUMA(caps) < 0)
        goto no_memory;

    if (virCapabilitiesAddHostMigrateTransport(caps,
                                               "tcp") < 0)
        goto no_memory;

    if ((guest = virCapabilitiesAddGuest(caps,
                                         VIR_DOMAIN_OSTYPE_EXE,
                                         caps->host.arch,
                                         NULL,
                                         NULL,
                                         0,
                                         NULL)) == NULL)
        goto no_memory;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_LXCTOOLS,
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto no_memory;

    return caps;

 no_memory:
    virObjectUnref(caps);
    return NULL;

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

    /*if (VIR_ALLOC_N(ret, retlen) < 0) {
        return NULL;
    }*/
    if ((ret = malloc(retlen)) == NULL) {
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

/*
 * str is callee allocated
 */
int lxctoolsReadConfigItem(struct lxc_container* cont, const char* item, char** str)
{
    int ret_len;
    if (VIR_ALLOC_N(*str, 64) < 0)
        goto error;
    if (( ret_len = cont->get_config_item(cont,
                                         item,
                                         *str,
                                         64) ) < 0){
       goto error;
    }
    if (ret_len >= 64) {
        if (VIR_ALLOC_N(*str, ret_len) < 0)
            goto error;
        if (( ret_len = cont->get_config_item(cont,
                                             item,
                                             *str,
                                             ret_len) ) < 0){
             goto error;
        }
    }
    return 0;      
 error: 
     virReportError(VIR_ERR_OPERATION_FAILED, "error on reading config for container: '%s'", cont->error_string);
     *str = NULL;
     return -1;
}

unsigned short countVCPUs(const char* cpustring)
{
    int i = 0;
    unsigned short cnt = 1;
    while (cpustring[i] != '\0') {
        if(cpustring[i++] == ',') {
            cnt++;
        }
    }
    return cnt;
}

static unsigned long long memToULL(char* memory_str)
{
     size_t len = strlen(memory_str);
     char size_unit = '\0';
     unsigned long long ret;
     if (memory_str[len-1] > '9') { //memory_str are \n\o terminated
        size_unit = memory_str[len-1];
        memory_str[len-1] = '\0';
     }
     sscanf(memory_str, "%llu", &ret);
     switch(size_unit) {
     case 'g':
     case 'G': ret*=1024ull;
     case 'm':
     case 'M': ret*=1024ull;
     case 'k':
     case 'K': break;
     default : ret/=1024ull;
     }

     return ret;
}

int lxctoolsSetNetConfig(lxctoolsConffilePtr conffile, virDomainDefPtr def)
{
    int ret = -1;
    char *mac_str = NULL;
 
    if (lxctoolsConffileRemoveItems(conffile, "lxc.network.") < 0)
        goto cleanup;

    if (lxctoolsConffileAddComment(conffile, "begin: generated network configuration") < 0)
        goto cleanup;

    for (size_t i = 0; i != def->nnets; i++) {
        if (def->nets[i]->type != VIR_DOMAIN_NET_TYPE_BRIDGE) {
            virReportError(VIR_ERR_NO_SUPPORT, "%s", _("only network type bridge is currently supported."));
            goto cleanup;
        }

        if (lxctoolsConffileAddItem(conffile, "lxc.network.type", "veth") < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s", _("failed to set lxc.network.type to veth"));
            goto cleanup;
        }

        if (VIR_ALLOC_N(mac_str, VIR_MAC_STRING_BUFLEN) < 0)
            goto cleanup;
        
        if (lxctoolsConffileAddItem(conffile, 
                                    "lxc.network.hwaddr", 
                                    virMacAddrFormat(&def->nets[i]->mac, mac_str)) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s", "failed to set lxc.network.hwaddr");
            goto cleanup;
        }

        if (lxctoolsConffileAddItem(conffile, "lxc.network.link", def->nets[i]->data.bridge.brname) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s", "failed to set lxc.network.link");
            goto cleanup;
        }

        if (def->nets[i]->linkstate == VIR_DOMAIN_NET_INTERFACE_LINK_STATE_UP) {
            if (lxctoolsConffileAddItem(conffile, "lxc.network.flags", "up") < 0)
                goto cleanup;
        }
    }
    if (lxctoolsConffileAddComment(conffile, "end: generated network configuration") < 0)
        goto cleanup;
    ret = 0;
 cleanup:
    VIR_FREE(mac_str);
    return ret;
}

static int lxctoolsReadNetConfig(struct lxc_container* cont, virDomainDefPtr def)
{
    virDomainNetDefPtr net = NULL;
    char* item_str = NULL;
    int ret = -1;
    size_t net_cnt;
    char** net_types = NULL;
    char* config_str = NULL;

    if (lxctoolsReadConfigItem(cont, "lxc.network", &item_str) < 0) {
        goto cleanup;
    }
    if (item_str == NULL || item_str[0] == '\0') {
        ret = 0; //No Network config is ok.
        goto cleanup;
    }
    net_types = virStringSplitCount(item_str, "\n", SIZE_MAX, &net_cnt);
    VIR_FREE(item_str);
    net_cnt--; //Last element is always empty
    while (net_cnt-- > 0) {
        if (VIR_ALLOC(net) < 0) {
            goto cleanup;
        }
        if (strcmp(net_types[net_cnt], "veth") == 0) {
            net->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "'%s'", "only network type veth is supported");
            goto cleanup;
        }
        if (virAsprintf(&config_str, "lxc.network.%lu.hwaddr", net_cnt) < 0) {
            goto cleanup;
        }
        if (lxctoolsReadConfigItem(cont, config_str, &item_str) < 0) {
            goto cleanup;
        }
        if (item_str != NULL && item_str[0] != '\0') {
            if (virMacAddrParse(item_str, &net->mac) < 0) {
                 goto cleanup;
            }
        } else {
            goto cleanup;
        }
        VIR_FREE(config_str);
        config_str=NULL;
        VIR_FREE(item_str);
        item_str=NULL;

        if (virAsprintf(&config_str, "lxc.network.%lu.link", net_cnt) < 0) {
            goto cleanup;
        }
        if (lxctoolsReadConfigItem(cont, config_str, &item_str) < 0) {
            goto cleanup;
        }
        if (item_str != NULL && item_str[0] != '\0') {
            if (VIR_STRDUP(net->data.bridge.brname, item_str) < 0) {
                goto cleanup;
            }
        }
        VIR_FREE(config_str);
        config_str=NULL;
        VIR_FREE(item_str);
        item_str=NULL;

        if (virAsprintf(&config_str, "lxc.network.%lu.flags", net_cnt) < 0) {
            goto cleanup;
        }
        if (lxctoolsReadConfigItem(cont, config_str, &item_str) < 0) {
            goto cleanup;
        }
        if (item_str != NULL && item_str[0] != '\0') {
            if (strcmp(item_str, "up") == 0) {
                net->linkstate = VIR_DOMAIN_NET_INTERFACE_LINK_STATE_UP;
            } else {
                net->linkstate = VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN;
            }
        } else {
            net->linkstate = VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN;
        }
        VIR_FREE(config_str);
        config_str=NULL;
        VIR_FREE(item_str);
        item_str=NULL;


        if (virDomainNetInsert(def, net) < 0) {
            goto cleanup;
        }   
    }


    ret = 0;
 cleanup:
    virStringFreeList(net_types);
    if (ret==-1) VIR_FREE(net);
    VIR_FREE(item_str);
    return ret;   
}

int lxctoolsSetFSConfig(lxctoolsConffilePtr conffile, virDomainDefPtr def)
{
    int ret = -1;
    bool rootfs_set = false;
    char *item_buf = NULL;
    if (lxctoolsConffileRemoveItems(conffile, "lxc.mount.entry") < 0)
        goto cleanup;

    if (lxctoolsConffileAddComment(conffile, "begin: generated filesystem configuration") < 0)
        goto cleanup;

    for (size_t i=0; i < def->nfss; i++) {
        if (def->fss[i]->type != VIR_DOMAIN_FS_TYPE_MOUNT) {
            virReportError(VIR_ERR_NO_SUPPORT, "%s", 
                           _("only fs type 'mount' is currently supported"));
            continue;
        }
        
        if (def->fss[i]->fsdriver != VIR_DOMAIN_FS_DRIVER_TYPE_PATH &&
               def->fss[i]->fsdriver != VIR_DOMAIN_FS_DRIVER_TYPE_DEFAULT) {
            virReportError(VIR_ERR_NO_SUPPORT, "%s",
                               _("only fs driver type 'path' is currently supported"));
            continue;
        }
        
        if (strcmp(def->fss[i]->dst, "/") == 0) {
            if (lxctoolsConffileSetItem(conffile, "lxc.rootfs", def->fss[i]->src) < 0) {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s", _("could not set rootfs"));
                goto cleanup;
            }
            rootfs_set = true;
        } else {
            if (def->fss[i]->dst[0] != '/') {
                virReportError(VIR_ERR_OPERATION_FAILED, "Destination '%s' does not contain a leading '/'", def->fss[i]->dst);
                goto cleanup;
            }
            
            if (virAsprintf(&item_buf,
                            "%s %s none bind,create=dir 0 0",
                            def->fss[i]->src, def->fss[i]->dst+1) < 0) {
                goto cleanup;
            }
            if (lxctoolsConffileAddItem(conffile, "lxc.mount.entry", item_buf) < 0)
                goto cleanup;
            VIR_FREE(item_buf);
            item_buf = NULL;
        }
    }

    if (lxctoolsConffileAddComment(conffile, "end: generated filesystem configuration") < 0)
        goto cleanup;

    if (!rootfs_set) {
        virReportError(VIR_ERR_NO_ROOT, "%s", _("missing rootfs configuration"));
        goto cleanup;
    }
    ret = 0;
 cleanup:
    VIR_FREE(item_buf);
    return ret;
}

static int lxctoolsReadFSConfig(lxctoolsConffilePtr conffile, virDomainDefPtr def)
{

    virDomainFSDefPtr fs = NULL;
    char* item_str = NULL;
    size_t splitcnt;
    char** splitlist = NULL;

    if ((item_str = lxctoolsConffileGetItem(conffile, "lxc.rootfs")) == NULL) {
        goto error;
    }
    if (item_str[0] == '\0') {
        virReportError(VIR_ERR_OPERATION_FAILED, "'%s'", "Domain has no rootfs config-item");
        goto error;
    }
    if (VIR_ALLOC(fs) < 0) {
        goto error;
    }

    fs->type = VIR_DOMAIN_FS_TYPE_MOUNT;
    splitlist = virStringSplitCount(item_str, ":", 3, &splitcnt);
    
    if (splitcnt == 1) { //Type is PATH
        fs->fsdriver = VIR_DOMAIN_FS_DRIVER_TYPE_PATH;
        fs->src = item_str;
        virStringFreeList(splitlist);
    } else {
        virReportError(VIR_ERR_OPERATION_FAILED, "'%s'", "Domain rootfs type is currently not supported");
        goto error;
    }
    if (VIR_STRDUP(fs->dst, "/") != 1)
        goto error;

 
    if (virDomainFSInsert(def, fs) < 0) {
        goto error;
    }
    item_str = NULL;
    splitlist = NULL;

    if ((splitlist = lxctoolsConffileGetItemlist(conffile, "lxc.mount.entry", &splitcnt)) == NULL) {
        goto error;
    }
    if (splitlist[0] != NULL) {
        size_t param_cnt;
        char** params;
        while (splitcnt-- > 0) {
            params = virStringSplitCount(splitlist[splitcnt], " ", 6, &param_cnt);
            if (param_cnt != 6) {
                virReportError(VIR_ERR_OPERATION_FAILED, "The following entry has to few parameters: '%s'", splitlist[splitcnt]);
                goto error;
            }
            if (VIR_ALLOC(fs) < 0) {
                goto error;
            }
            if (strcmp(params[2], "none") == 0 && strstr(params[3],"bind") != NULL) {
                fs->type = VIR_DOMAIN_FS_TYPE_MOUNT;
                fs->fsdriver = VIR_DOMAIN_FS_DRIVER_TYPE_PATH;
                if (VIR_STRDUP(fs->src, params[0]) < 0) {
                    goto error;
                }
                if (virAsprintf(&fs->dst, "/%s", params[1]) < 0) {
                    goto error;
                }
                if (strstr(params[3], "ro") != NULL) {
                    fs->readonly = true;
                }
                if (virDomainFSInsert(def, fs) < 0) {
                    goto error;
                }
            }

            virStringFreeList(params);

        }
        virStringFreeList(splitlist);
        splitlist = NULL;
    }

    VIR_FREE(item_str);


    return 0;
error:
    virStringFreeList(splitlist);
    VIR_FREE(fs);
    VIR_FREE(item_str);
    return -1;
}

int lxctoolsCheckStaticConfig(virDomainDefPtr def)
{
    virNodeInfoPtr nodeinfo = NULL;
    if (VIR_ALLOC(nodeinfo) < 0) {
        return -1;
    }
    
    if (nodeGetInfo(nodeinfo) < 0) {
        return -1;
    }

 /*   if (def->mem.max_memory != nodeinfo->memory) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s", _("setting max_memory is unssuported"));
        return -1;
    }*/

    if (def->cpumask && virBitmapLastSetBit(def->cpumask) >= nodeinfo->cpus) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s", _("to many cpus set in cpuset"));
        return -1;
    }
    
    return 0;
}

int lxctoolsSetBasicConfig(lxctoolsConffilePtr conffile, virDomainDefPtr def)
{
    int ret = -1;
    char *item_str = NULL;

 /*   if (lxctoolsConffileRemoveItems(conffile, "lxc.include") < 0)
        goto cleanup;

    if (def->metadata != NULL) {
        xmlNodePtr node = def->metadata->children;
        while (node != NULL) {
            if (node->children != NULL && node->children->type == XML_TEXT_NODE) {

                if (xmlStrcmp(node->children->name, (const xmlChar*)"lxctools:include")) {

                    if (lxctoolsConffileSetItem(conffile, "lxc.include", (const char*)node->children->content) < 0)
                        goto cleanup;
                } else if (xmlStrcmp(node->children->name, (const xmlChar*)"lxctools:livemigration-iterations")) {
                    VIR_DEBUG("found migration iterations: %s", node->children->content);
                }
            } else {
                VIR_DEBUG("found include node but no child text node");
            }
            node = node->next;
        }
        if (node == NULL) {
            virReportError(VIR_ERR_OPERATION_FAILED, "'%s'", "found metadata, but no known child element");
            if (lxctoolsConffileRemoveItems(conffile, "lxc.include") < 0)
                 goto cleanup;

        }
    }
*/
    if (( item_str = lxctoolsConffileGetItem(conffile, "lxc.utsname")) == NULL)
        goto cleanup;
    if (item_str[0] == '\0') {
        if (lxctoolsConffileSetItem(conffile, "lxc.utsname", def->name) < 0)
            goto cleanup;
    }
    VIR_FREE(item_str);
    item_str = NULL;


    if (def->os.arch == VIR_ARCH_I686) {
        if (lxctoolsConffileSetItem(conffile, "lxc.arch", "i686") < 0)
            goto cleanup;
    } else if (def->os.arch == VIR_ARCH_X86_64) {
        if (lxctoolsConffileSetItem(conffile, "lxc.arch", "x86_64") < 0)
            goto cleanup;
    } else {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s", _("Unknown architecture"));
        goto cleanup;
    }

    if ((item_str = virBitmapFormat(def->cpumask)) == NULL) 
        goto cleanup;
printf("'%s'\n", item_str);
    if (item_str[0] != '\0') {
        if (lxctoolsConffileSetItem(conffile, "lxc.cgroup.cpuset.cpus", item_str) < 0)
            goto cleanup;
    } else {
        if (lxctoolsConffileRemoveItems(conffile, "lxc.cgroup.cpuset.cpus") < 0)
            goto cleanup;
    }
    VIR_FREE(item_str);
    item_str = NULL;

    if (def->cputune.sharesSpecified) {
        if (virAsprintf(&item_str, "%llu", def->cputune.shares) < 0)
            goto cleanup;
        if (lxctoolsConffileSetItem(conffile, "lxc.cgroup.cpu.shares", item_str) < 0)
            goto cleanup;
    } else {
        if (lxctoolsConffileRemoveItems(conffile, "lxc.cgroup.cpu.shares") < 0)
            goto cleanup;
    }
    VIR_FREE(item_str);
    item_str = NULL;

    if (def->cputune.period != 0) {
        if (virAsprintf(&item_str, "%llu", def->cputune.period) < 0)
            goto cleanup;
        if (lxctoolsConffileSetItem(conffile, "lxc.cgroup.cpu.cfs_period_us", item_str) < 0)
            goto cleanup;
    } else {
        if (lxctoolsConffileRemoveItems(conffile, "lxc.cgroup.cpu.cfs_period_us") < 0)
            goto cleanup;
    }
    VIR_FREE(item_str);
    item_str = NULL;

    if (def->cputune.quota != 0) {
        if (virAsprintf(&item_str, "%llu", def->cputune.quota) < 0)
            goto cleanup;
        if (lxctoolsConffileSetItem(conffile, "lxc.cgroup.cpu.cfs_quota_us", item_str) < 0)
            goto cleanup;
    } else {
        if (lxctoolsConffileRemoveItems(conffile, "lxc.cgroup.cpu.cfs_quota_us") < 0)
            goto cleanup;
    }
    VIR_FREE(item_str);
    item_str = NULL;

    if (def->mem.total_memory != def->mem.cur_balloon) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s", _("max_balloon  and cur_balloon have to have the same value. Memory ballooning is not neccessary for containerss."));
        goto cleanup;
    }
    if (def->mem.total_memory != 0) {
        if (virAsprintf(&item_str, "%lluk", def->mem.total_memory) < 0)
            goto cleanup;
        if (lxctoolsConffileSetItem(conffile, "lxc.cgroup.memory.limit_in_bytes", item_str) < 0)
            goto cleanup;
    } else {
        if (lxctoolsConffileRemoveItems(conffile, "lxc.cgroup.memory.limit_in_bytes") < 0)
            goto cleanup;
    }
    VIR_FREE(item_str);
    item_str = NULL;

    if (def->mem.soft_limit != 0 && def->mem.soft_limit < def->mem.cur_balloon) {
        if (virAsprintf(&item_str, "%lluk", def->mem.soft_limit) < 0)
            goto cleanup;
        if (lxctoolsConffileSetItem(conffile, "lxc.cgroup.memory.soft_limit_in_bytes", item_str) < 0)
            goto cleanup;
    } else {
        if (lxctoolsConffileRemoveItems(conffile, "lxc.cgroup.memory.soft_limit_in_bytes") < 0)
            goto cleanup;
    }
    VIR_FREE(item_str);
    item_str = NULL;

    if ((item_str = virBitmapFormat(virDomainNumatuneGetNodeset(def->numa,NULL,0))) == NULL) 
        goto cleanup;

    if (item_str[0] != '\0') {
        if (lxctoolsConffileSetItem(conffile, "lxc.cgroup.cpuset.mems", item_str) < 0)
            goto cleanup;
    } else {
        if (lxctoolsConffileRemoveItems(conffile, "lxc.cgroup.cpuset.mems") < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(item_str);
    return ret;

}

int lxctoolsReadConfig(struct lxc_container* cont, virDomainDefPtr def)
{
    char* item_str = NULL;
    virNodeInfoPtr nodeinfo = NULL;
    lxctoolsConffilePtr conffile = NULL;

    if (VIR_ALLOC(nodeinfo) < 0) {
        goto error;
    }
    
    if (nodeGetInfo(nodeinfo) < 0) {
        goto error;
    }
    
    if (VIR_ALLOC(conffile) < 0)
        goto error;

    if (lxctoolsConffileRead(conffile, cont->config_file_name(cont)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "'%s'", _("failed to read conffile"));
        goto error;
    }
    if ((item_str = lxctoolsConffileGetItem(conffile, "lxc.arch")) == NULL) {
        goto error;
    }
    if (item_str[0] != '\0') {
        if (strcmp(item_str, "x86") == 0 || strcmp(item_str, "i686")  == 0) {
            def->os.arch = VIR_ARCH_I686;
        }
        else if (strcmp(item_str, "x86_64") == 0 || strcmp(item_str, "amd64") == 0) {
            def->os.arch = VIR_ARCH_X86_64;
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED, "Unknown architecture '%s'.", item_str);
            goto error;
        }
    }
    VIR_FREE(item_str);
    item_str = NULL;

    if ((item_str = lxctoolsConffileGetItem(conffile, "lxc.cgroup.cpuset.cpus")) == NULL){
        goto error;
    }
    if (item_str[0] == '\0') {
        if (virDomainDefSetVcpusMax(def, nodeinfo->cpus) < 0)
            goto error;
        def->cpumask = virBitmapNew(nodeinfo->cpus);
        virBitmapSetAll(def->cpumask);
    } else {
        int cpunum;
        if ( (cpunum = virBitmapParse(item_str, &def->cpumask, nodeinfo->cpus) ) < 0) {
            goto error;
        }  
        if (virDomainDefSetVcpusMax(def, cpunum) < 0)
            goto error;
    }

    if (virDomainDefSetVcpus(def, virDomainDefGetVcpusMax(def)) < 0)
        goto error;
   
    VIR_FREE(item_str);
    item_str = NULL;

    if ((item_str = lxctoolsConffileGetItem(conffile, "lxc.cgroup.cpu.shares")) == NULL) {
        goto error;
    }
    if (item_str[0] != '\0') {
        unsigned long shares;
        sscanf(item_str, "%lu", &shares);
        def->cputune.shares = shares;
        def->cputune.sharesSpecified = true;
    }

    VIR_FREE(item_str);
    item_str = NULL;

    if ((item_str = lxctoolsConffileGetItem(conffile, "lxc.cgroup.cpu.cfs_period_us")) == NULL) {
        goto error;
    }
    if (item_str[0] != '\0') {
        unsigned long long period;
        sscanf(item_str, "%llu", &period);
        def->cputune.period = period;
    }

    VIR_FREE(item_str);
    item_str = NULL;

    if ((item_str = lxctoolsConffileGetItem(conffile, "lxc.cgroup.cpu.cfs_quota_us")) == NULL) {
        goto error;
    }
    if (item_str[0] != '\0') {
        long long quota;
        sscanf(item_str, "%llu", &quota);
        def->cputune.quota = quota;
    }

    VIR_FREE(item_str);
    item_str = NULL;


    if ((item_str = lxctoolsConffileGetItem(conffile, "lxc.cgroup.memory.limit_in_bytes")) == NULL) {
        goto error;
    }
    if (item_str[0] == '\0') {
        virDomainDefSetMemoryTotal(def, nodeinfo->memory);
    } else {
        virDomainDefSetMemoryTotal(def, memToULL(item_str)); 
    }


    def->mem.cur_balloon = virDomainDefGetMemoryTotal(def);
//    def->mem.max_memory = nodeinfo->memory;
//    def->mem.memory_slots = 1; //maybe delete max_memory alltogether

    VIR_FREE(item_str);
    item_str = NULL;
    if ((item_str = lxctoolsConffileGetItem(conffile, "lxc.cgroup.memory.soft_limit_in_bytes")) == NULL) {
        goto error;
    }
    if (item_str[0] != '\0') {
        def->mem.soft_limit = memToULL(item_str);
    }

    VIR_FREE(item_str);
    item_str = NULL;

    if ((item_str = lxctoolsConffileGetItem(conffile, "lxc.cgroup.cpuset.mems")) == NULL) {
        goto error;
    }
    if (item_str[0] != '\0') {
        virBitmapPtr nodeset;
        if (virBitmapParse(item_str, &nodeset, nodeinfo->nodes) < 0) {
            goto error;
        }  
        if (virDomainNumatuneSet(def->numa,
                             true,
                             VIR_DOMAIN_NUMATUNE_PLACEMENT_DEFAULT,
                             VIR_DOMAIN_NUMATUNE_MEM_STRICT,
                             nodeset) < 0 ) {
            goto error;
        }
    }

    VIR_FREE(item_str);
    item_str = NULL;

    if ((item_str = lxctoolsConffileGetItem(conffile, "lxc.include")) == NULL) {
        goto error;
    }

    //lxc.include is optional!
    if (item_str[0] != '\0') {
        def->metadata = xmlNewNode(NULL, (const xmlChar*) "metadata");
        xmlNewTextChild(def->metadata, NULL, (const xmlChar*) (const xmlChar*)"lxctools:include", (const xmlChar*)item_str);
    }

    VIR_FREE(item_str);
    item_str = NULL;
    if (lxctoolsReadFSConfig(conffile, def) < 0)
        goto error;

    if (lxctoolsReadNetConfig(cont, def) < 0)
        goto error;

    return 0;
 error:
    VIR_FREE(item_str);
    VIR_FREE(nodeinfo);
    return -1;
}

static int addToBeginning(FILE* fd, char* str)
{
    int ret = -1;
    char* buffer;
    size_t length;
    size_t strlength = strlen(str);
    fseek(fd, 0, SEEK_END);
    length = ftell(fd);
    fseek(fd, 0, SEEK_SET);
    if (VIR_ALLOC_N(buffer, length)) {
        goto cleanup;
    }
    if (read(fileno(fd), buffer, length) != length) {
        goto cleanup;
    }
    
    fseek(fd, 0, SEEK_SET);
    if (write(fileno(fd), str, strlength) != strlength) {
        goto cleanup;
    }
    if (write(fileno(fd), buffer, length) != length) {
        goto cleanup;
    }
    ret = 0;
cleanup:
    VIR_FREE(buffer);
    return ret;
}

static int lxctoolsReadUUID(struct lxc_container* cont, unsigned char* uuid)
{
    int ret = -1;
    const char* config_path = cont->config_file_name(cont);
    FILE* fd;
    size_t read_len = 0;
    char* linestr = NULL;
    if ((fd = fopen(config_path, "r+")) == NULL) {
        goto cleanup;
    }
    if (getline(&linestr, &read_len, fd) < 0) {
        goto cleanup;
    }
    if (strncmp(linestr, "# UUID:", 7) != 0) {
        char uuid_str[7+VIR_UUID_STRING_BUFLEN+1] = "# UUID:";
        if (virUUIDGenerate(uuid) < 0) {
           goto cleanup;
        }
        if (virUUIDFormat(uuid, uuid_str+7) == NULL) {
            goto cleanup;
        }
        uuid_str[7+VIR_UUID_STRING_BUFLEN-1] = '\n';
        uuid_str[7+VIR_UUID_STRING_BUFLEN] = '\0';
        if (addToBeginning(fd, uuid_str) < 0) {
            goto cleanup;
        }
        ret = 0;
        goto cleanup;
    }

    linestr[strlen(linestr)-1] = '\0';
    if (virUUIDParse(linestr+7, uuid) < 0) {
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(linestr);
    fclose(fd);
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
        if (!(def = virDomainDefNew()))
            goto cleanup;

        def->virtType = VIR_DOMAIN_VIRT_LXCTOOLS;
        if (!cret[i]->is_running(cret[i])) {
            def->id = -1;
        } else {
            def->id = cret[i]->init_pid(cret[i]);
        }

        
        if (lxctoolsReadUUID(cret[i], def->uuid) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s", "could not parse UUID");
            goto cleanup;
        } 


        def->os.type = VIR_DOMAIN_OSTYPE_EXE;
        def->name = names[i];

        if (lxctoolsReadConfig(cret[i], def) < 0){
            goto cleanup;
        }
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


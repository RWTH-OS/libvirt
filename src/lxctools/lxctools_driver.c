/*
 * lxctools_driver.c: core driver methods for managing LXCTool Containers
 *
 * Copyright (C) 2010-2015 Red Hat, Inc.
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
#include <lxc/lxccontainer.h>

#include "virerror.h"
#include "datatypes.h"
#include "virbuffer.h"
#include "nodeinfo.h"
#include "viralloc.h"
#include "virfile.h"
#include "virtypedparam.h"
#include "virlog.h"
#include "vircommand.h"
#include "viruri.h"
#include "virstats.h"
#include "virstring.h"
#include "access/viraccessapicheck.h"
#include "lxctools_conf.h"

#include "lxctools_driver.h"

#define VIR_FROM_THIS VIR_FROM_LXCTOOLS

VIR_LOG_INIT("lxctools.lxctools_driver");

static int lxctoolsDomainGetInfo(virDomainPtr dom,
                                 virDomainInfoPtr info)
{
    struct lxctools_driver *driver = dom->conn->privateData;
    struct lxc_container *cont;
    virDomainObjPtr vm;
    const char* state;
    char* config_item = NULL;
    int config_item_len;
    vm = virDomainObjListFindByName(driver->domains, dom->name);
    
    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching id"));
        goto cleanup;
    }

    cont = vm->privateData;
    state = cont->state(cont);
    info->state = lxcState2virState(state);
    
    /* check CPU config */
    if ((config_item_len = cont->get_config_item(cont,
                    "lxc.cgroup.cpuset.cpus", NULL, 0)) < 0)
        goto cleanup;
    
    if (VIR_ALLOC_N(config_item, config_item_len) < 0)
        goto cleanup;
    
    if (config_item_len > 0 && 
            cont->get_config_item(cont, "lxc.cgroup.cpuset.cpus", 
                                  config_item, config_item_len) 
            != config_item_len) {
        goto cleanup;
    }
    if ((config_item_len > 0 &&
        (info->nrVirtCpu = strtol(config_item, NULL, 10))) ||
            (info->nrVirtCpu = getNumOfHostCPUs(dom->conn)) == 0) {
        goto cleanup; 
    } 
    VIR_FREE(config_item);

    /* check max memory config */
    if ((config_item_len = cont->get_config_item(cont,
                    "lxc.cgroup.memory.limit_in_bytes", NULL, 0)) < 0)
        goto cleanup;
    
    if (VIR_ALLOC_N(config_item, config_item_len) < 0)
        goto cleanup;
    
    if (config_item_len > 0 && 
            cont->get_config_item(cont, "lxc.cgroup.memory.limit_in_bytes", 
                                  config_item, config_item_len) 
            != config_item_len) {
        goto cleanup;
    }
    if (config_item_len > 0) {
        info->maxMem = convertMemorySize(config_item, config_item_len); 
    } else if ((info->maxMem = getHostMemory(dom->conn)) == 0) {
        goto cleanup; 
    } 
    VIR_FREE(config_item);
    
    /* check memory usage */
    if ((config_item_len = cont->get_cgroup_item(cont,
                    "memory.usage_in_bytes", NULL, 0)) < 0)
        goto cleanup;
    if (VIR_ALLOC_N(config_item, config_item_len) < 0)
        goto cleanup;
    if (config_item_len > 0 && 
            cont->get_cgroup_item(cont, "memory.usage_in_bytes", 
                                  config_item, config_item_len) 
            != config_item_len) {
        goto cleanup;
    }
    if (config_item_len > 0) {
        info->memory = (strtol(config_item, NULL, 10)>>10);
    } else {
        info->memory = 0L;
    } 
    VIR_FREE(config_item);

    /* check cpu time */
    if ((config_item_len = cont->get_cgroup_item(cont,
                    "cpuacct.usage", NULL, 0)) < 0)
        goto cleanup;
    
    if (VIR_ALLOC_N(config_item, config_item_len) < 0)
        goto cleanup;
    
    if (config_item_len > 0 && 
            cont->get_cgroup_item(cont, "cpuacct.usage", 
                                  config_item, config_item_len) 
            != config_item_len) {
        goto cleanup;
    }
    if (config_item_len > 0) {
       info->cpuTime = strtol(config_item, NULL, 10);
    } else {
       info->cpuTime = 0L;
    } 
    VIR_FREE(config_item);
    return 0;
cleanup:
    if(vm)
        virObjectUnlock(vm);
    VIR_FREE(config_item);
    return -1;
}

static virDomainPtr lxctoolsDomainLookupByID(virConnectPtr conn,
                                             int id)
{
    struct lxctools_driver* driver = conn->privateData;
    virDomainObjPtr obj;
    virDomainPtr dom = NULL;

    obj = virDomainObjListFindByID(driver->domains, id);

    if (!obj) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
    } else { 
        dom = virGetDomain(conn, obj->def->name, obj->def->uuid);
        if (dom)
            dom->id = obj->def->id;
    }
    
    if(obj)
        virObjectUnlock(obj);
    return dom;
}

static virDomainPtr lxctoolsDomainLookupByName(virConnectPtr conn,
                                               const char *name)
{
    struct lxctools_driver* driver = conn->privateData;
    virDomainObjPtr obj;
    virDomainPtr dom = NULL;

    obj = virDomainObjListFindByName(driver->domains, name);

    if (!obj) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
    } else { 
        dom = virGetDomain(conn, obj->def->name, obj->def->uuid);
        if (dom)
            dom->id = obj->def->id;
    }
    
    if(obj)
        virObjectUnlock(obj);
    return dom;   
}

static int lxctoolsConnectListDomains(virConnectPtr conn, int *ids, int nids)
{
    struct lxctools_driver* driver = conn->privateData;
    int n;
    n = virDomainObjListGetActiveIDs(driver->domains, ids, nids,
                                     NULL, NULL);

    return n;

}

static int lxctoolsConnectListDefinedDomains(virConnectPtr conn,
                                             char **const names,
                                             int nnames)
{
    struct lxctools_driver *driver = conn->privateData; 
    return virDomainObjListGetInactiveNames(driver->domains, names, nnames,
                                            NULL, NULL);  
}

static int lxctoolsConnectClose(virConnectPtr conn)
{
    struct lxctools_driver *driver = conn->privateData;
    lxctoolsFreeDriver(driver);
    conn->privateData = NULL;
    return 0;
}

static int lxctoolsConnectNumOfDefinedDomains(virConnectPtr conn)
{
    struct lxctools_driver *driver = conn->privateData;
    return virDomainObjListNumOfDomains(driver->domains, false, NULL, NULL);
}

static int lxctoolsConnectNumOfDomains(virConnectPtr conn)
{
    struct lxctools_driver *driver = conn->privateData;
    return virDomainObjListNumOfDomains(driver->domains, true, NULL, NULL);    
}

static virDrvOpenStatus lxctoolsConnectOpen(virConnectPtr conn,
					  virConnectAuthPtr auth ATTRIBUTE_UNUSED,
					  unsigned int flags)
{
    struct lxctools_driver *driver = NULL;
    const char* lxcpath = NULL;
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if(conn->uri == NULL) {
       if (!(lxcpath = lxc_get_global_config_item("lxc.lxcpath"))) {
           virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                          _("could not get lxc.lxcpath config item"));
           return VIR_DRV_OPEN_DECLINED;
       }
       if (!virFileExists(lxcpath)) {
           free((void*)lxcpath);
           return VIR_DRV_OPEN_DECLINED;
       }
       if (!virFileIsDir(lxcpath)) {
           free((void*)lxcpath);
	       return VIR_DRV_OPEN_DECLINED;
       }

       if(!(conn->uri = virURIParse("lxctools:///"))) {
           goto cleanup;
       }
    } else {
       /* Is schme for 'lxctools'? */
       if(conn->uri->scheme == NULL ||
          STRNEQ(conn->uri->scheme, "lxctools"))
          return VIR_DRV_OPEN_DECLINED;

       /* Is no server name given? (local driver) */
       if (conn->uri->server != NULL)
           return VIR_DRV_OPEN_DECLINED;

       /* is path supported? */
       if (conn->uri->path != NULL &&
           STRNEQ(conn->uri->path, "/")) {
           virReportError(VIR_ERR_INTERNAL_ERROR,
                          _("Unexpected lxctools URI path '%s', try lxctools:///"),
                          conn->uri->path);
           goto cleanup;
       }
       if (!(lxcpath = lxc_get_global_config_item("lxc.lxcpath"))) {
           virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                          _("could not get lxc.lxcpath config item"));
           goto cleanup;
       }
       if (!virFileExists(lxcpath)) {
           virReportError(VIR_ERR_INTERNAL_ERROR, 
                          _("lxctools directory '%s' does not exist"),
                          lxcpath);
           goto cleanup;
       }
       if (!virFileIsDir(lxcpath)) {
           virReportError(VIR_ERR_INTERNAL_ERROR,
                          _("lxctools directory '%s' is not a directory"),
                          lxcpath);
            goto cleanup;
       }

    }
    
    if (VIR_ALLOC(driver) < 0)
       goto cleanup;

    driver->path = lxcpath;
    driver->domains = NULL;

    if ((driver->numOfDomains = list_all_containers(driver->path, NULL, NULL)) < 0){
       goto cleanup;     
    }
    if (!(driver->domains = virDomainObjListNew())) {
       goto cleanup;
    }

    if (lxctoolsLoadDomains(driver) < 0) {
       virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                      _("error while loading domains"));
           
       goto cleanup;
    } 

    conn->privateData = driver;

    return VIR_DRV_OPEN_SUCCESS;
cleanup:
    free((char*)lxcpath);
    if (driver) {
        if (driver->domains)
            virObjectUnref(driver->domains);
        VIR_FREE(driver);
    }
    return VIR_DRV_OPEN_ERROR;
}

static int
lxctoolsNodeGetInfo(virConnectPtr conn ATTRIBUTE_UNUSED,
                               virNodeInfoPtr nodeinfo)
{
    return nodeGetInfo(nodeinfo);
}    

static int
lxctoolsNodeGetCPUStats(virConnectPtr conn ATTRIBUTE_UNUSED,
                                   int cpuNum,
                                   virNodeCPUStatsPtr params,
                                   int *nparams,
                                   unsigned int flags)
{
    return nodeGetCPUStats(cpuNum, params, nparams, flags);
}

static int 
lxctoolsNodeGetMemoryStats(virConnectPtr conn ATTRIBUTE_UNUSED,
                                      int cellNum,
                                      virNodeMemoryStatsPtr params,
                                      int *nparams,
                                      unsigned int flags)
{
    return nodeGetMemoryStats(cellNum, params, nparams, flags);
}

static int
lxctoolsNodeGetCellsFreeMemory(virConnectPtr conn ATTRIBUTE_UNUSED,
                               unsigned long long *freeMems,
                               int startCell,
                               int maxCells)
{
    return nodeGetCellsFreeMemory(freeMems, startCell, maxCells);
}

static unsigned long long
lxctoolsNodeGetFreeMemory(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    unsigned long long freeMem;
    if(nodeGetMemory(NULL, &freeMem) < 00)
        return 0;
    return freeMem;
}

static int
lxctoolsNodeGetCPUMap(virConnectPtr conn ATTRIBUTE_UNUSED,
                      unsigned char **cpumap,
                      unsigned int *online,
                      unsigned int flags)
{
    return nodeGetCPUMap(cpumap, online, flags);
}

static virHypervisorDriver lxctoolsHypervisorDriver = {
    .name = "LXCTOOLS",
    .connectOpen = lxctoolsConnectOpen, /* 0.0.1 */
    .connectNumOfDomains = lxctoolsConnectNumOfDomains, /* 0.0.1 */
    .connectClose = lxctoolsConnectClose, /* 0.0.2 */
    .connectListDomains = lxctoolsConnectListDomains, /* 0.0.2 */
    .domainLookupByID = lxctoolsDomainLookupByID, /* 0.0.2 */
    .domainGetInfo = lxctoolsDomainGetInfo, /* 0.0.2 */
    .connectNumOfDefinedDomains = lxctoolsConnectNumOfDefinedDomains, /* 0.0.2 */
    .connectListDefinedDomains = lxctoolsConnectListDefinedDomains, /* 0.0.2 */
    .domainLookupByName = lxctoolsDomainLookupByName, /* 0.0.2 */
    .nodeGetInfo = lxctoolsNodeGetInfo, /* 0.0.3 */
    .nodeGetCPUStats = lxctoolsNodeGetCPUStats, /* 0.0.3 */
    .nodeGetMemoryStats = lxctoolsNodeGetMemoryStats, /* 0.0.3 */
    .nodeGetCellsFreeMemory = lxctoolsNodeGetCellsFreeMemory, /* 0.0.3 */
    .nodeGetFreeMemory = lxctoolsNodeGetFreeMemory, /* 0.0.3 */
    .nodeGetCPUMap = lxctoolsNodeGetCPUMap, /* 0.0.3 */
};

static virConnectDriver lxctoolsConnectDriver = {
    .hypervisorDriver = &lxctoolsHypervisorDriver,
};

int lxctoolsRegister(void)
{
    return virRegisterConnectDriver(&lxctoolsConnectDriver,
                                    false);
}

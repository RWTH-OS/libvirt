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
#include "domain_conf.h"
#include "access/viraccessapicheck.h"

#include "lxctools_driver.h"

#define VIR_FROM_THIS VIR_FROM_LXCTOOLS

VIR_LOG_INIT("lxctools.lxctools_driver");

#define LXCTOOLS_NB_MEM_PARAM 3

#define LXCTOOLS_PATH "/var/lib/lxc"

struct lxctools_driver {
    char* path;
    virDomainObjListPtr domains;
    int numOfDomains;
};
/*
static void printUUID(const unsigned char *uuid)
{
    char str[VIR_UUID_STRING_BUFLEN];
    virUUIDFormat(uuid, str);
    printf("UUID: %s\n", str);

}*/

static int lxctoolsConnectListDomains(virConnectPtr conn, int *ids, int nids)
{
    struct lxctools_driver* driver = conn->privateData;
    int n;
    n = virDomainObjListGetActiveIDs(driver->domains, ids, nids,
                                     NULL, NULL);

    return n;

}

static void lxctoolsFreeDriver(struct lxctools_driver* driver)
{
    if(!driver)
        return;
    VIR_FREE(driver->path);
    virObjectUnref(driver->domains);
    VIR_FREE(driver);
}

static int lxctoolsConnectClose(virConnectPtr conn)
{
    struct lxctools_driver *driver = conn->privateData;
    lxctoolsFreeDriver(driver);
    conn->privateData = NULL;
    return 0;
}

static int lxctoolsLoadDomains(struct lxctools_driver *driver)
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

static int lxctoolsConnectNumOfDomains(virConnectPtr conn)
{
    struct lxctools_driver *driver = conn->privateData;
    return driver->numOfDomains;
}

static virDrvOpenStatus lxctoolsConnectOpen(virConnectPtr conn,
					  virConnectAuthPtr auth ATTRIBUTE_UNUSED,
					  unsigned int flags)
{
    struct lxctools_driver *driver;
    int path_len;
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if(conn->uri == NULL) {
       if(!virFileExists(LXCTOOLS_PATH))
          return VIR_DRV_OPEN_DECLINED;

       if(!virFileIsDir(LXCTOOLS_PATH))
	  return VIR_DRV_OPEN_DECLINED;

       if(!(conn->uri = virURIParse("lxctools:///")))
          return VIR_DRV_OPEN_ERROR;
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
          return VIR_DRV_OPEN_ERROR;
       }
       if (!virFileExists(LXCTOOLS_PATH)) {
           virReportError(VIR_ERR_INTERNAL_ERROR, 
                          _("lxctools directory '%s' does not exist"),
                          LXCTOOLS_PATH);
           return VIR_DRV_OPEN_ERROR;
       }
       if (!virFileIsDir(LXCTOOLS_PATH)) {
           virReportError(VIR_ERR_INTERNAL_ERROR,
                          _("lxctools directory '%s' is not a directory"),
                          LXCTOOLS_PATH);
           return VIR_DRV_OPEN_ERROR;
       }

    }
    
    if (VIR_ALLOC(driver) < 0)
       return VIR_DRV_OPEN_ERROR;

    if ((path_len = strlen(LXCTOOLS_PATH)) < 0) {
       VIR_FREE(driver);
       return VIR_DRV_OPEN_ERROR;     
    }

    if (VIR_ALLOC_N(driver->path, path_len+1) < 0) {
       VIR_FREE(driver);
       return VIR_DRV_OPEN_ERROR;
    }

    if (!virStrncpy(driver->path, LXCTOOLS_PATH, path_len, path_len+1)) {
       VIR_FREE(driver->path);
       VIR_FREE(driver);
       return VIR_DRV_OPEN_ERROR;
    }
    if ((driver->numOfDomains = list_all_containers(driver->path, NULL, NULL)) < 0){
       VIR_FREE(driver->path);
       VIR_FREE(driver);
       return VIR_DRV_OPEN_ERROR;
    }
    if (!(driver->domains = virDomainObjListNew())) {
       VIR_FREE(driver->path);
       VIR_FREE(driver);
       return VIR_DRV_OPEN_ERROR;
    }

    if (lxctoolsLoadDomains(driver) < 0) {
       virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                      _("error while loading domains"));
           
       VIR_FREE(driver->path);
       VIR_FREE(driver);
       return VIR_DRV_OPEN_ERROR;
    } 

    conn->privateData = driver;

    return VIR_DRV_OPEN_SUCCESS;
}

static virHypervisorDriver lxctoolsHypervisorDriver = {
    .name = "LXCTOOLS",
    .connectOpen = lxctoolsConnectOpen, /* 0.3.1 */
    .connectNumOfDomains = lxctoolsConnectNumOfDomains, /* 0.3.1 */
    .connectClose = lxctoolsConnectClose,
    .connectListDomains = lxctoolsConnectListDomains,
};

static virConnectDriver lxctoolsConnectDriver = {
    .hypervisorDriver = &lxctoolsHypervisorDriver,
};

int lxctoolsRegister(void)
{
    return virRegisterConnectDriver(&lxctoolsConnectDriver,
                                    false);
}

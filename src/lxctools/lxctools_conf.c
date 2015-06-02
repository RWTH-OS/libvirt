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

#include "viralloc.h"

#include "lxctools_conf.h"

#define VIR_FROM_THIS VIR_FROM_LXCTOOLS

/*
static void printUUID(const unsigned char *uuid)
{
    char str[VIR_UUID_STRING_BUFLEN];
    virUUIDFormat(uuid, str);
    printf("UUID: %s\n", str);

}*/


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
    VIR_FREE(driver->path);
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

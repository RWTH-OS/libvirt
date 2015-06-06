/*
 * lxctools_conf.h: config information for LXCTOOLS domains
 *
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright (C) 2006, 2007 Binary Karma.
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
 *
 */

#ifndef LXCTOOLS_CONF_H
# define LXCTOOLS_CONF_H

# include "internal.h"
#include <lxc/lxccontainer.h>

#include "domain_conf.h"

struct lxctools_driver {
    const char* path;
    virDomainObjListPtr domains;
    int numOfDomains;
};


void lxctoolsFreeDriver(struct lxctools_driver* driver);

int lxctoolsLoadDomains(struct lxctools_driver *driver);

unsigned long convertMemorySize(char* memory_str, unsigned int strlen);

unsigned int getNumOfHostCPUs(virConnectPtr conn);
unsigned long getHostMemory(virConnectPtr conn);

virDomainState lxcState2virState(const char* state);

#endif /* LXCTOOLS_CONF_H */

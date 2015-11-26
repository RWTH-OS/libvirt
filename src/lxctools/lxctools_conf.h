/*
 * lxctools_conf.h: config information for LXCTOOLS domains
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
    virCapsPtr caps;
    unsigned long version;
    virDomainXMLOptionPtr xmlopt;
    struct lxctools_migrate_data* md;
};
virCapsPtr lxctoolsCapabilitiesInit(void);
char* getContainerNameFromPath(const char* path);
char* concatPaths(const char* path1, const char* path2);
void lxctoolsFreeDriver(struct lxctools_driver* driver);

int lxctoolsLoadDomains(struct lxctools_driver *driver);

unsigned long convertMemorySize(char* memory_str, unsigned int strlen);

unsigned int getNumOfHostCPUs(virConnectPtr conn);
unsigned long getHostMemory(virConnectPtr conn);
bool criuExists(void);
virDomainState lxcState2virState(const char* state);
int lxctoolsReadConfig(struct lxc_container* cont, virDomainDefPtr def);
unsigned short countVCPUs(const char* cpustring);
int lxctoolsReadConfigItem(struct lxc_container* cont, const char* item, char** str);

#endif /* LXCTOOLS_CONF_H */

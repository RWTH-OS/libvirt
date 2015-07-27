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

#ifndef LXCTOOLS_MIGRATION_H
# define LXCTOOLS_MIGRATION_H

# include "internal.h"
#include <pthread.h>

#include "domain_conf.h"

#define LXCTOOLS_LIVE_MIGRATION_ITERATIONS 1


struct lxctools_migrate_data {
    pid_t criusrv_pid;
    pid_t copysrv_pid;
    pthread_t *server_thread;
};

bool startCopyProc(struct lxctools_migrate_data* md, const char* criu_port, const char* copy_port, const char* path, pid_t pid, const char* dconnuri, bool live);

bool startCopyServer(struct lxctools_migrate_data* md, const char* criu_port, const char* copy_port, const char* path, bool live);

bool waitForMigrationProcs(struct lxctools_migrate_data* md);
bool createTmpfs(const char* path);

int restoreContainer(struct lxc_container *cont, bool live);

#endif /* LXCTOOLS_MIGRATION_H */

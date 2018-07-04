/*
 * lxctools_migration.h: function for migrating LXCTOOLS domains
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

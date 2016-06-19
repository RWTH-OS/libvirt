/*
 * lxctools_filecpy_client.h: client logic for filecopy
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

#ifndef LXCTOOLS_FILECPY_CLIENT_H
# define LXCTOOLS_FILECPY_CLIENT_H

# include "internal.h"

#include "lxctools_filecpy_types.h"

int client_connect(const char* address, const char* port);
statustype_t client_receive_status(int socket);
int client_senddir(const char* dir);
void client_close(int sock);

#endif /* LXCTOOLS_FILECPY_CLIENT_H */

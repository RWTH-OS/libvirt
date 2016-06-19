/*
 * lxctools_filecpy_server.h: server logic for filecopy
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

#ifndef LXCTOOLS_FILECPY_SERVER_H
# define LXCTOOLS_FILECPY_SERVER_H

# include "internal.h"

#include "lxctools_filecpy_types.h"

int server_start(const char* port);
int server_connect_block(int sock);
int server_send_status(int socket, statustype_t status);
statustype_t server_receive_status_noblock(int socket);
int server_receive_files(int socket, const char* dir);
int server_close(int socket);

#endif /* LXCTOOLS_FILECPY_SERVER_H */

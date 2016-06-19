#/*
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

#ifndef LXCTOOLS_FILECPY_TYPES_H
# define LXCTOOLS_FILECPY_TYPES_H

#include "lxctools_filecpy_types.h"

#define DIRCPY_H

//walkdir_send_type type argument defines
#define TYPE_REG 0x00
#define TYPE_DIR 0x01
#define TYPE_LNK 0x02
#define TYPE_ENDTOKEN 0x0F

typedef uint8_t cpytype_t;

#define STATUS_RDY 0xF0
#define STATUS_ACK 0xF1
#define STATUS_END 0xFD
#define STATUS_AGAIN 0xFE
#define STATUS_ERR 0xFF

typedef uint8_t statustype_t;

#endif /* LXCTOOLS_FILECPY_TYPES_H */

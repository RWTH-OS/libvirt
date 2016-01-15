/*
 * lxctools_conffile.h: lxc config file handling for LXCTOOLS domains
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

#ifndef LXCTOOLS_CONFFILE_H
# define LXCTOOLS_CONFFILE_H

# include "internal.h"

typedef struct _lxctoolsConffileEntry lxctoolsConffileEntry;
typedef lxctoolsConffileEntry *lxctoolsConffileEntryPtr;
struct _lxctoolsConffileEntry
{
    lxctoolsConffileEntryPtr next;
    char* line;
};

typedef struct _lxctoolsConffile lxctoolsConffile;
typedef lxctoolsConffile *lxctoolsConffilePtr;
struct _lxctoolsConffile
{
    lxctoolsConffileEntryPtr first;
    lxctoolsConffileEntryPtr last;
};

int lxctoolsConffileAppfirst(lxctoolsConffilePtr conffile, lxctoolsConffileEntryPtr item);
int lxctoolsConffileAppend(lxctoolsConffilePtr conffile, lxctoolsConffileEntryPtr item);
void lxctoolsConffileFree(lxctoolsConffilePtr conffile);
int lxctoolsConffileRead(lxctoolsConffilePtr conffile, const char* filename);
int lxctoolsConffileWrite(lxctoolsConffilePtr conffile, const char* filename);
//value_store is callee allocated and must be VIR_FREE'd by caller
char* lxctoolsConffileGetItem(lxctoolsConffilePtr conffile, const char* key);

int lxctoolsConffileSetItem(lxctoolsConffilePtr conffile, const char* key, const char* value);

int lxctoolsConffileGetUUID(lxctoolsConffilePtr conffile, char* uuid_store);
int lxctoolsConffileAddUUID(lxctoolsConffilePtr conffile, unsigned char* uuid);
char **lxctoolsConffileGetItemlist(lxctoolsConffilePtr conffile,
                                   const char* key,
                                   size_t* tokcount);
int lxctoolsConffileRemoveItems(lxctoolsConffilePtr,
                            const char* key);
int lxctoolsConffileAddItem(lxctoolsConffilePtr conffile,
                        const char* key,
                        const char* value);
//void lxctoolsConffilePrint(lxctoolsConffilePtr conffile);
#endif /* LXCTOOLS_CONFFile_H */

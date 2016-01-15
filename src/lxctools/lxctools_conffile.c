/*
 * lxctools_conffile.c: lxc config file handling for LXCTOOLS domains
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
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "viralloc.h"
#include "virstring.h"
#include "virfile.h"
#include "virlog.h"
#include "lxctools_conffile.h"
#include "virerror.h"
#include "viruuid.h"

#define VIR_FROM_THIS VIR_FROM_LXCTOOLS

VIR_LOG_INIT("lxctools.lxctools_conffile");

void lxctoolsConffileFree(lxctoolsConffilePtr conffile)
{
    if (conffile == NULL)
        return;
    lxctoolsConffileEntryPtr it;
    while (conffile->first != NULL) {
        it = conffile->first;
        conffile->first = it->next;
        VIR_FREE(it->line);
        VIR_FREE(it);
    }
    VIR_FREE(conffile);
}

int lxctoolsConffileAppfirst(lxctoolsConffilePtr conffile, lxctoolsConffileEntryPtr item)
{
    if (conffile == NULL)
        return -1;
    if (conffile->last == NULL && conffile->first == NULL)
        conffile->last = item;
    item->next = conffile->first;
    conffile->first = item;
    return 1;
}

int lxctoolsConffileAppend(lxctoolsConffilePtr conffile, lxctoolsConffileEntryPtr item)
{
    if (conffile == NULL)
        return -1;
    if (conffile->last == NULL && conffile->first == NULL)
        conffile->first = item;
    else if (conffile->last != NULL)
        conffile->last->next = item;
    else
        return -1;
    conffile->last = item;
    item->next = NULL;
    return 1;
}

void lxctoolsConffilePrint(lxctoolsConffilePtr conffile)
{
    lxctoolsConffileEntryPtr it = conffile->first;
    while (it != NULL) {
        printf("'%s'\n", it->line);
        it = it->next;
    }

}

int
lxctoolsConffileRead(lxctoolsConffilePtr conffile, const char* filename)
{
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read_len;
    lxctoolsConffileEntryPtr entry = NULL;
    int ret = -1;
    if (conffile == NULL)
        goto cleanup;

    conffile->first = NULL;
    conffile->last = NULL;
    if ( (fp = fopen(filename, "r")) == NULL) {
        virReportError(VIR_ERR_OPERATION_FAILED, "'%s'", _("failed to open conffile"));
        goto cleanup;
    }
    while ((read_len = getline(&line, &len, fp)) != -1) {
        if (VIR_ALLOC(entry) < 0) {
            goto cleanup;
        }
        entry->line = line;
        if (lxctoolsConffileAppend(conffile, entry) == -1) {
            goto cleanup;
        }
        line = NULL;
        len = 0;
    }
    line = NULL;
    ret = 0;
 cleanup:
    fclose(fp);
    free(line);
    return ret;
}

int
lxctoolsConffileWrite(lxctoolsConffilePtr conffile, const char* filename)
{
    FILE *fp;
    int ret = -1;
    lxctoolsConffileEntryPtr it;
    if (conffile == NULL)
        goto cleanup;

    if ( (fp = fopen(filename, "w")) == NULL) {
        virReportError(VIR_ERR_OPERATION_FAILED, "'%s'", _("failed to open conffile" ));
        goto cleanup;
    }
    
    it = conffile->first;

    while (it != NULL) {
        if (write(fileno(fp), it->line, strlen(it->line)) != strlen(it->line)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "'%s'", _("failed to write to file"));
            goto cleanup;
        }
        it = it->next;
    }

    ret = 0;
 cleanup:
    fclose(fp);
    return ret;
}

/**
 * return value is callee allocated and must be freed
 */
char *lxctoolsConffileGetItem(lxctoolsConffilePtr conffile,
                              const char* key)
{
    char* value = NULL;
    char* ret = NULL;
    size_t keylen = strlen(key);
    lxctoolsConffileEntryPtr it = conffile->first;
    while (it != NULL) {
        if (strncmp(key, it->line, keylen) == 0) {
            value = it->line+keylen;
            virSkipSpaces((const char**)&value);
            if (value[0] != '=')
                return NULL;
            virSkipSpaces((const char**)&value);
            if (VIR_STRNDUP(ret, value, strlen(value)-1) < 0)
                return NULL;
            
            return ret;
        }
        it = it->next;
    }
    return NULL;
}

/**
 * return a stringlist with all config values for all keys starting with the given key
 * free with virStringListFree
 */
char **lxctoolsConffileGetItemlist(lxctoolsConffilePtr conffile,
                                   const char* key,
                                   size_t* tokcount)
{
    size_t ntokens = 0;
    size_t maxtokens = 0;
    char** tokens = NULL;
    char* value;
    size_t keylen = strlen(key);
    int i;
    lxctoolsConffileEntryPtr it = conffile->first;
    while (it != NULL) {
        if (strncmp(key, it->line, keylen) == 0) {
            value = it->line+keylen;
            virSkipSpaces((const char**)&value);
            if (value[0] != '=')
                continue;
            virSkipSpaces((const char**)&value);

            if (VIR_RESIZE_N(tokens, maxtokens, ntokens, 1) < 0)
                goto error;

            if (VIR_STRNDUP(tokens[ntokens], value, strlen(value)-1) < 0)
                goto error;

            ntokens++;
        }
        it = it->next;
    }
    if (VIR_RESIZE_N(tokens, maxtokens, ntokens, 1) < 0)
        goto error;
    tokens[ntokens] = NULL;

    if (tokcount)
        *tokcount = ntokens;

    return tokens;

 error:
    for (i = 0; i < ntokens; i++)
        VIR_FREE(tokens[i]);
    VIR_FREE(tokens);
    return NULL;
}

/**
 * removes ALL items beginning with key
 * return number of removed entries or -1 on error
 */
int
lxctoolsConffileRemoveItems(lxctoolsConffilePtr conffile,
                            const char* key)
{
    lxctoolsConffileEntryPtr prev_it = NULL;
    lxctoolsConffileEntryPtr it;
    lxctoolsConffileEntryPtr del_it;
    size_t keylen = strlen(key);
    size_t cnt=0;
    if (conffile == NULL || key == NULL)
        return -1;
    it = conffile->first;
    while (it != NULL) {
        if (strncmp(key, it->line, keylen) == 0) {
            //delete old entry
            if (prev_it == NULL) {
                conffile->first = it->next;
            } else {
                prev_it->next = it->next;
            }
            if (it->next == NULL)
                conffile->last = prev_it;
            del_it = it;
            it = it->next;
            VIR_FREE(del_it->line);
            VIR_FREE(del_it);
            cnt++;
        } else {
            prev_it = it;
            it = it->next;
        }
    }
    return cnt;
}

int
lxctoolsConffileAddItem(lxctoolsConffilePtr conffile,
                        const char* key,
                        const char* value)
{
    lxctoolsConffileEntryPtr it;
    if (conffile == NULL || key == NULL || value == NULL)
        return -1;
    //create new entry
    if (VIR_ALLOC(it) < 0)
        return -1;
    if (virAsprintf(&it->line, "%s = %s\n", key, value) < 0)
        return -1;
    return lxctoolsConffileAppend(conffile, it);
}

/**
 * return 0 on change, 1 on add and -1 on error
 */
int
lxctoolsConffileSetItem(lxctoolsConffilePtr conffile,
                        const char* key,
                        const char* value)
{
    lxctoolsConffileEntryPtr prev_it = NULL;
    lxctoolsConffileEntryPtr it = conffile->first;
    size_t keylen = strlen(key);
    while (it != NULL) {
        if (strncmp(key, it->line, keylen) == 0) {
        /* replace already present config item */
            //delete old entry
            if (prev_it == NULL)
                conffile->first = it->next;
            else
                prev_it->next = it->next;
            
            if (conffile->last == it)
                conffile->last = prev_it;
            VIR_FREE(it->line);
            VIR_FREE(it);
            //create new entry
            if (VIR_ALLOC(it) < 0)
                return -1;
            if (virAsprintf(&it->line, "%s = %s\n", key, value) < 0)
                return -1;
            //add entry
            if (conffile->last == NULL && conffile->first == NULL)
                conffile->first = it;
            else if (conffile->last != NULL)
                conffile->last->next = it;
            else
                return -1;
            conffile->last = it;

            return 0;
        }
        prev_it = it;
        it = it->next;
    }
    /* add new config item */
    //create new entry
    if (VIR_ALLOC(it) < 0)
        return -1;
    if (virAsprintf(&it->line, "%s = %s\n", key, value) < 0)
        return -1;
    //add entry
    return lxctoolsConffileAppend(conffile, it);
}

int lxctoolsConffileAddUUID(lxctoolsConffilePtr conffile, unsigned char* uuid)
{
    lxctoolsConffileEntryPtr it = NULL;
    char uuid_str[7+VIR_UUID_STRING_BUFLEN+1] = "# UUID:";
    int ret = -1;
    if (virUUIDGenerate(uuid) < 0) {
       goto cleanup;
    }
    if (virUUIDFormat(uuid, uuid_str+7) == NULL) {
       goto cleanup;
    }
    uuid_str[7+VIR_UUID_STRING_BUFLEN-1] = '\n';
    uuid_str[7+VIR_UUID_STRING_BUFLEN] = '\0';

    if (VIR_ALLOC(it) < 0) {
       goto cleanup;
    }

    if (lxctoolsConffileAppfirst(conffile, it) < 0) {
        VIR_FREE(it);
        goto cleanup;
    }
    ret = 0;
cleanup:
    return ret;
}

// uuid_store is caller allocated and at least VIR_UUID_STRING_BUFLEN  long
int lxctoolsConffileGetUUID(lxctoolsConffilePtr conffile, char* uuid_store)
{
    if (conffile == NULL || conffile->first == NULL)
        return -1;

    if (strncmp(conffile->first->line, "# UUID:", 7) != 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s", "failed to find UUID in conffile");
        return -1;
    }

    if (strncpy(uuid_store, conffile->first->line + 7, VIR_UUID_STRING_BUFLEN) != 0)
        return -1;

    return 0;
}

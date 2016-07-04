/*
 * lxctools_filecpy_client.c: lxctools filecopy client used to transfer data during migration
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

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <sys/sendfile.h>
#include <ftw.h>

#include "virlog.h"
#include "virerror.h"

#include "lxctools_filecpy_client.h"

#define VIR_FROM_THIS VIR_FROM_LXCTOOLS

VIR_LOG_INIT("lxctools.lxctools_filecpy_client");

int g_socket;

int client_connect(const char* address, const char* port)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(address);
    addr.sin_port = htons(atoi(port));

    if ((g_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        VIR_DEBUG("failed to create socket\n");
        return -1;
    }

    if (connect(g_socket, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        VIR_DEBUG("failed to connect\n");
        return -1;
    }

    VIR_DEBUG("connected to %s\n", inet_ntoa(addr.sin_addr));
    return g_socket;
}

static int walkdir_send_type(int sock, cpytype_t type)
{
    if (send(sock, &type, sizeof(type), 0) != sizeof(type)) {
        VIR_DEBUG("error while sending type: %u\n", type);
        return -1;
    }
    return 0;
}

int client_close(int sock)
{
    int error;
    if (sock > 0) {
        if ((error = shutdown(sock, SHUT_RDWR)) < 0) {
            VIR_DEBUG("ERROR: socket shutdown returned %d", error);
            return -1;
        }
        if ((error = close(sock)) < 0) {
            VIR_DEBUG("ERROR: socket close returned %d", error);
            return -1;
        }
    }
    return -1;
}

static int walkdir_send_name(int sock, const char* name, size_t filename_length)
{
    if (send(sock, &filename_length, sizeof(filename_length), 0) != sizeof(filename_length)) {
        VIR_DEBUG("error while sending filename_length: %lu\n", filename_length);
        return -1;
    }
    if (send(sock, name, filename_length, 0) != filename_length) {
       VIR_DEBUG("error while sending filename: '%s' (%lu)\n", name, filename_length);
        return -1;
    }
    return 0;
}
static ssize_t walkdir_send_file(int sock, int file, size_t file_size)
{
    ssize_t sent_data;
    if (send(sock, &file_size, sizeof(file_size), 0) != sizeof(file_size)) {
        VIR_DEBUG("error while sending filesize: %lu\n", file_size);
        return -1;
    }

    sent_data = sendfile(sock, file, NULL, file_size);
    while (sent_data < file_size) {
        VIR_DEBUG("sent %ld / %lu bytes", sent_data, file_size);
        sent_data += sendfile(sock, file, NULL, file_size - sent_data);
    }
    VIR_DEBUG("sent %ld / %lu bytes", sent_data, file_size);
 /*   if (sent_data != file_size) {
        VIR_DEBUG("not everthing sent: return %ld expected %lu\n", sent_data, file_size);
        VIR_DEBUG("errno: %s", strerror(errno));
        return -1;
    }*/
    return sent_data;
}

static int walkdir_send_reg(int sock, const char* filename, const char *sendname, size_t filesize)
{
    size_t len;
    int file;
    int ret = -1;
    if ((file = open(filename, O_RDONLY | O_NOFOLLOW)) < 0) {
        VIR_DEBUG("errno: %s", strerror(errno));
        goto err;
    }

    if (walkdir_send_type(sock, TYPE_REG) < 0) {
        VIR_DEBUG("could not send file type for '%s'", sendname);
        goto err;
    }
    len = strlen(sendname) + 1;
    if (walkdir_send_name(sock, sendname, len) < 0) {
        VIR_DEBUG("could not send file name for '%s'", sendname);
        goto err;
    }

    if (walkdir_send_file(sock, file, filesize) != filesize) {
        VIR_DEBUG("could not send file content for '%s'", sendname);
        goto err;
    }
    VIR_DEBUG("sent file '%s' (%lu byte(s)).\n", sendname, filesize);
    ret = 0;
 err:
    close(file);
    return ret;
}

static int walkdir_send_lnk(int sock, const char* lnkname, const char *sendname, size_t lnksize)
{
    char* lnkdest = NULL;
    int ret = -1;
    ssize_t lnkdest_size;
    if ((lnkdest = malloc(lnksize+1)) == NULL)
        return -1;

    if ((lnkdest_size = readlink(lnkname, lnkdest, lnksize+1)) < 0 || lnkdest_size > lnksize) {
        VIR_DEBUG("could not read link or link size increased\n");
        goto err;
    }

    lnkdest[lnksize] = '\0';

    if (walkdir_send_type(sock, TYPE_LNK) < 0) {
        goto err;
    }

    if (walkdir_send_name(sock, sendname, strlen(sendname)+1) < 0) {
        goto err;
    }

    if (walkdir_send_name(sock, lnkdest, lnkdest_size+1) < 0) {
        goto err;
    }
    VIR_DEBUG("sent link '%s' (%lu byte(s)) -> '%s' (%lu byte(s)).\n", sendname, strlen(sendname)+1, lnkdest, lnkdest_size+1);

    ret = 0;
 err:
    free(lnkdest);
    return ret;
}

static int walkdir_send_dir(int sock, const char* dirname)
{
    int ret = -1;

    if (walkdir_send_type(sock, TYPE_DIR) < 0) {
        goto err;
    }

    if (walkdir_send_name(sock, dirname, strlen(dirname)+1) < 0) {
        goto err;
    }

    VIR_DEBUG("sent dir '%s' (%lu byte(s)).\n", dirname, strlen(dirname)+1);

    ret = 0;
 err:
    return ret;
}

size_t path_offset = 0;

static int walkdir_item(const char *fpath, const struct stat *sb, int typeflag, struct FTW* ftwbuf ATTRIBUTE_UNUSED)
{
    const char *spath;
  //  statustype_t status;
    if (path_offset == 0 && typeflag == FTW_D) {
        path_offset = strlen(fpath)+1;
        return 0;  //we are at ".". This does not need to be transmitted.
    }
    spath = fpath + path_offset;
    
    VIR_DEBUG("about to send '%s'", spath);
 /*   if ((status = client_receive_status(g_socket)) != STATUS_ACK) {
        VIR_DEBUG("received wrong status (not STATUS_ACK) %d", status);
        return -4;
    }
    VIR_DEBUG("received ack");*/
    if (typeflag == FTW_F) {
        if (walkdir_send_reg(g_socket, fpath, spath, sb->st_size) < 0)
            return -2;
    } else if (typeflag == FTW_D) {
        if (walkdir_send_dir(g_socket, spath) < 0) {
            return -3;
        }
    } else if (typeflag == FTW_SL) {
        if (walkdir_send_lnk(g_socket, fpath, spath, sb->st_size) < 0) {
            return -4;
        }

    } else {
        VIR_DEBUG("'%s' could not be sent because the filetype is unsupported or an error occured.\n", fpath);
    }
    return 0;
}

int client_senddir(const char* dir)
{

    path_offset = 0;
    VIR_DEBUG("starting copyclient...");
    if (nftw(dir, walkdir_item, 15, FTW_PHYS) < 0) {
        VIR_DEBUG("nftw failed on '%s'\n", dir);
        return -1;
    }
   /* if (client_receive_status(g_socket) != STATUS_ACK) {
        VIR_DEBUG("received wrong status (not STATUS_ACK)");
        return -4;
    }*/
    if (walkdir_send_type(g_socket, TYPE_ENDTOKEN) < 0) {
        VIR_DEBUG("could not send endtoken");
        return -1;
    }
    VIR_DEBUG("send endtoken");
    return 0;
}

statustype_t client_receive_status(int socket)
{
    statustype_t status;
    ssize_t recvlen;

    if ((recvlen = recv(socket, &status, sizeof(status), 0)) < 0) {
        VIR_DEBUG("error while recv'ing\n");
        return STATUS_ERR; 
    }
    return status;
}

/*
int main(int argc, char* argv[])
{
    if (argc != 4) {
        printf("wrong number of args\n");
        exit(1);
    }


    client_connect(argv[1], argv[2]);
    if (client_receive_status(sock) != STATUS_RDY) 
        printf("not ready!\n");
    else
        printf("ready!\n");
    client_senddir(argv[3]);
    client_close(sock);
    return 0;
}*/

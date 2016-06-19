/*
 * lxctools_filecpy_server.c: lxctools filecopy server used to transfer data during migration
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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <errno.h>

#include "virlog.h"
#include "virerror.h"

#include "lxctools_filecpy_server.h"

#define VIR_FROM_THIS VIR_FROM_LXCTOOLS

VIR_LOG_INIT("lxctools.lxctools_filecpy_server");


struct server_data {
    ssize_t available;
    char buf[4096];
    size_t i_begin;
};


int server_start(const char* port)
{
    int sock;
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(atoi(port));

    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        VIR_DEBUG("failed to create socket\n");
        return -1;
    }

    if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        VIR_DEBUG("failed to bind\n");
        return -1;
    }

    if (listen(sock, 1) < 0) {
        VIR_DEBUG("failed to listen\n");
        return -1;
    }
    VIR_DEBUG("listening on port %s", port);
    return sock;
}

int server_connect_block(int sock)
{
    struct sockaddr_in peer_addr;
    int clientsock;
    unsigned int peer_addr_len = sizeof(peer_addr);

    if ((clientsock = accept(sock, (struct sockaddr*) &peer_addr, &peer_addr_len)) < 0) {
        VIR_DEBUG("failed to create clientsock\n");
        return -1;
    }

    VIR_DEBUG("connected to %s\n", inet_ntoa(peer_addr.sin_addr));
    return clientsock;
}

static int data_handler_stringify(const char* data, size_t size, void* param)
{
    VIR_DEBUG("stringify called");
    static size_t string_size;
    char** string = (char**)param;
    int reset = 0;
    if (*string == NULL) {
        string_size = 1;
        reset = 1;
    }
    if ((*string = realloc(*string, string_size+size)) == NULL)
        return -1;
    if (reset)
        (*string)[0] = '\0'; //make string empty for concat
    string_size += size;
    strncat(*string, data, size);
    VIR_DEBUG("strigify finished");
    return 0;
}

static int data_handler_filewriter(const char* data, size_t size, void* param)
{
    int *filefd = (int*)param;
    if (write(*filefd, data, size) != size) {
        VIR_DEBUG("an error occured during buffer write\n");
        VIR_DEBUG("errno: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}


static cpytype_t server_receive_type(int socket, struct server_data *data)
{
    cpytype_t type;
    ssize_t recvbuf;
    while (data->available < sizeof(type)) {
        if (data->available > 0)
            memmove(data->buf, data->buf+data->i_begin, data->available);
        if ((recvbuf = recv(socket, data->buf+data->available, 4096-data->available, 0)) < 0) {
            VIR_DEBUG("error while recv'ing\n");
            return -1;;
        }
        data->available+=recvbuf;
        data->i_begin = 0;
    }
    type = *((cpytype_t*)(data->buf+data->i_begin));
    data->i_begin += sizeof(type);
    data->available -= sizeof(type);
    return type;
}

static size_t server_receive_size(int socket, struct server_data *data)
{
    size_t size;
    ssize_t recvbuf;
    while (data->available < sizeof(size)) {
        if (data->available > 0)
            memmove(data->buf, data->buf+data->i_begin, data->available);
        if ((recvbuf = recv(socket, data->buf+data->available, 4096-data->available, 0)) < 0) {
            VIR_DEBUG("error while recv'ing\n");
            return -1;;
        }
        data->available+=recvbuf;
        data->i_begin = 0;
    }
    size = *((size_t*)(data->buf+data->i_begin));
    data->i_begin += sizeof(size);
    data->available -= sizeof(size);
    return size;
}

static int server_receive(int socket, struct server_data *data, int (*data_handler)(const char*,size_t,void*), void* data_handler_param)
{
    size_t size;

    size = server_receive_size(socket, data);
VIR_DEBUG("expecting %lu bytes\n", size);
    //Data size is bigger than what is available -> do multiple retrieval iterations
    while (data->available >= 0 && size > data->available) {
VIR_DEBUG("19");
        if (data_handler(data->buf+data->i_begin, data->available, data_handler_param) < 0) {
            VIR_DEBUG("data handler error!\n");
            return -1;
        }
        size -= data->available;     //all available data has been consumed
VIR_DEBUG("data size was bigger");
        //Receive new data and reset i_begin
        if ((data->available = recv(socket, data->buf, 4096, 0)) < 0) {
            VIR_DEBUG("error while recv'ing\n");
            return -1;
        }
        data->i_begin = 0;
    }
VIR_DEBUG("20");
    //available data is bigger than data size -> retrieve and update i_begin and available
    if (data_handler(data->buf+data->i_begin, size, data_handler_param) < 0) {
        VIR_DEBUG("data handler error!\n");
        return -1;
    }
VIR_DEBUG("data size was smaller");
    data->i_begin += size;
    data->available -= size;
    return 0;
}

int server_close(int socket)
{
    if (socket > 0)
        close(socket);
    return 0;

}

static int recv_lnk(int socket, struct server_data* server_data, int dir_fd)
{
    char* lnkname = NULL;
    char* lnkdest = NULL;
    int ret = -1;

    if (server_receive(socket, server_data, data_handler_stringify, &lnkname) != 0) {
        VIR_DEBUG("server_receive was not successfull (on lnkname)!");
        goto err;
    }
    VIR_DEBUG("about to receive link '%s'", lnkname);

    if (server_receive(socket, server_data, data_handler_stringify, &lnkdest) != 0) {
        VIR_DEBUG("server_receive was not successfull (on lnkdest)!");
        goto err;
    }

    if (symlinkat(lnkdest, dir_fd, lnkname) < 0) {
        VIR_DEBUG("symlinkat: errno: %s", strerror(errno));
        goto err;
    }

    VIR_DEBUG("received symlink '%s' (%lu byte(s)) -> '%s' (%lu byte(s)).", lnkname, strlen(lnkname)+1, lnkdest, strlen(lnkdest)+1);

    ret = 0;
err:
    free(lnkname);
    free(lnkdest);
    return ret;
}

static int recv_reg(int socket, struct server_data* server_data, int dir_fd)
{
    char* msg = NULL;
    int filefd;
  //  struct stat statdata;
    int ret = -1;
    
    VIR_DEBUG("receiving new regular file");

    if (server_receive(socket, server_data, data_handler_stringify, &msg) != 0) {
        VIR_DEBUG("server_receive was not successfull (on filename)!");
        goto err;
    }

 //   VIR_DEBUG("about to receive reg '%s' at fd %d", msg, dir_fd);
    //open with permission 664
    filefd = openat(dir_fd, msg, O_RDWR | O_CREAT | O_NOFOLLOW, S_IRUSR | S_IWUSR |  S_IRGRP | S_IWGRP | S_IROTH);

    if (filefd < 0) {
        VIR_DEBUG("errno: %s", strerror(errno));
        goto err;
    }

    if (server_receive(socket, server_data, data_handler_filewriter, &filefd) != 0) {
        VIR_DEBUG("server_received was not successfull!");
        goto err;
    }
VIR_DEBUG("received reg!");
 /*   if (fstat(filefd, &statdata)) {
        VIR_DEBUG("cannot stat file");
        goto err;
    }

    VIR_DEBUG("received file '%s' (%lu byte(s)).", msg, statdata.st_size);*/

    ret = 0;
err:
    close(filefd);
    free(msg);
    return ret;
}

static int recv_dir(int socket, struct server_data* server_data, int dir_fd)
{
    char* dirname = NULL;
    int ret = -1;
    if (server_receive(socket, server_data, data_handler_stringify, &dirname) != 0) {
        VIR_DEBUG("server_receive was not successfull (on dir)!");
        goto err;
    }
    VIR_DEBUG("about to receive dir '%s' at fd %d", dirname, dir_fd);

    //permission 664
    if (mkdirat(dir_fd, dirname, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
        if (errno == EEXIST) {
            VIR_DEBUG("directory '%s' already exists. jump mkdir step", dirname);
        } else {
            VIR_DEBUG("errno: %s", strerror(errno));
            goto err;
        }
    }

    VIR_DEBUG("received dir '%s' (%lu byte(s)).", dirname, strlen(dirname)+1);

    ret = 0;
 err:
    return ret;
}

int server_receive_files(int socket, const char* dir)
{
    //DIR* dirptr;
    int dir_fd;
    struct server_data *server_data = NULL;
    cpytype_t filetype;
    int ret = -1;
    char flushbuf[512];
    if ((server_data = malloc(sizeof(server_data))) == NULL) {
        VIR_DEBUG("malloc failed");
        goto err;
    }

    server_data->available = 0;
    server_data->i_begin = 0;

    //remove this!
    while (recv(socket, flushbuf, 512, MSG_DONTWAIT) > 0) {
        VIR_DEBUG("flushed something");
    }

    if (server_send_status(socket, STATUS_ACK) < 0)
        goto err;
    filetype = server_receive_type(socket, server_data);

  /*  if ((dirptr = opendir(dir)) == NULL) {
        VIR_DEBUG("failed to openddir");
        goto err;
    }

    VIR_DEBUG("opened dir '%s' fd %d", dir, dirfd(dirptr)); */
    if ((dir_fd = open(dir, O_DIRECTORY | O_RDONLY)) < 0) {
        VIR_DEBUG("failed to open dir: %s", strerror(errno));
        goto err;
    }
    VIR_DEBUG("opened dir '%s' fd %d", dir, dir_fd);
    while (filetype != TYPE_ENDTOKEN) {
        if (filetype == TYPE_REG) {
            if (recv_reg(socket, server_data, dir_fd) < 0)
                goto err;
        } else if (filetype == TYPE_DIR) {
            if (recv_dir(socket, server_data, dir_fd) < 0)
                goto err;
        } else if (filetype == TYPE_LNK) {
            if (recv_lnk(socket, server_data, dir_fd) < 0) 
                goto err;
        } else {
            VIR_DEBUG("received something that is not supported (i.e. not a regular file, a symlink or a folder...");
            goto err;
        }
        if (server_send_status(socket, STATUS_ACK) < 0)
            goto err;
        VIR_DEBUG("send ack"); 
        filetype = server_receive_type(socket, server_data);
        VIR_DEBUG("received type %d", filetype);
    }
    VIR_DEBUG("received end token");
    ret = 0;
 err:
    free(server_data);
    return ret;
}

int server_send_status(int socket, statustype_t status)
{
    if (send(socket, &status, sizeof(status), 0) != sizeof(status)) {
        VIR_DEBUG("error while sending status: %u", status);
        return -1;
    }
    return 0;
}

statustype_t server_receive_status_noblock(int socket)
{
    statustype_t status;
    ssize_t recvlen;

    if ((recvlen = recv(socket, &status, sizeof(status), MSG_DONTWAIT)) < 0) {
        if(errno == EAGAIN)
            return STATUS_AGAIN;
        VIR_DEBUG("error while recv'ing");
        return STATUS_ERR; 
    }
    return status;
}
/*
int fileserver(const char* port, const char* dir)
{
    int socket;
    int ret = -1;

    if ((socket = server_connect(port)) < 0) {
        return ret;
    }
    server_send_status(socket, STATUS_RDY);
    ret = server_receive_files(socket, dir);
    server_closeconn(socket);

    return ret;
}

int main(int argc, char* argv[])
{
    if (argc != 3) {
        printf("wrong number of args\n");
        exit(1);
    }

    if (fileserver(argv[1], argv[2]) < 0)
        printf("error!\n");

    return 0;
}*/

/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the 
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include "tcp.h"

extern int h_errno;

int tcp_write(void *userdata, const void *_data, int len)
{
    int len_tmp = len;
    int n;
    const char *_data_tmp = _data;
    tcp_handle *h = userdata;
    while (len_tmp > 0) {
        n = write(h->sockfd, _data_tmp, len_tmp);
        if (n <= 0) {
            switch(errno) {
            case EAGAIN: case EINTR: continue;
            default:
                fprintf(stderr, "ERROR: Failed to send to network: %s\n",
                        strerror(errno));
                exit(1);
            }
        }
        len_tmp -= n;
        _data_tmp += n;
    }
    return len;
}

int tcp_read(void *userdata, void *_data, int len)
{
    int n, count = 0;
    unsigned char *data = _data;
    tcp_handle *h = userdata;
    while (len > 0) {
        // This xfer chunking is to mirror usb_read() implementation:
        int xfer = (len > 16*1024) ? 16*1024 : len;
        n = read(h->sockfd, data, xfer);
        if (n == 0) {
            fprintf(stderr, "ERROR: Failed to read network: "
                    "Unexpected end of file.");
            exit(1);
        } else if (n < 0) {
            switch(errno) {
            case EAGAIN: case EINTR: continue;
            default:
                fprintf(stderr, "ERROR: Failed to read network: %s",
                        strerror(errno));
                exit(1);
            }
        }
        count += n;
        len -= len;
        data += n;

        // Replicate a bug from usb_read():
        if (n < xfer)
            break;
    }
    return count;
}

int tcp_close(void *userdata)
{
    tcp_handle *h = userdata;
    return close(h->sockfd);
}

tcp_handle *tcp_open(const char *host)
{
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    tcp_handle *tcp = 0;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "ERROR: Can't open socket: %s\n", strerror(errno));
        exit(1);
    }

    server = gethostbyname(host);
    if (server == NULL) {
        fprintf(stderr, "ERROR: Can't find '%s': %s\n", host, hstrerror(h_errno));
        exit(1);
    }

    memset(&serv_addr, sizeof(serv_addr), 0);
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr,
           server->h_addr,
           server->h_length);
    serv_addr.sin_port = htons(1234);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) {
        fprintf(stderr, "ERROR: Unable to connect to %s: %s\n",
                host, strerror(errno));
        exit(1);
    }

    tcp = calloc(1, sizeof(tcp_handle));
    tcp->sockfd = sockfd;
    return tcp;
}


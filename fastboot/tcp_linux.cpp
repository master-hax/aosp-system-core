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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <netdb.h>
#include <netinet/in.h>

#include <memory>

#include "tcp.h"

#define HEADER_LEN 12

extern int h_errno;

class LinuxTcpTransport : public Transport {
  public:
    LinuxTcpTransport(int sockfd) : sockfd_(sockfd) {}
    ~LinuxTcpTransport() override;

    ssize_t Read(void* data, size_t len) override;
    ssize_t Write(const void* data, size_t len) override;
    int Close() override;

  private:
    int sockfd_;

    DISALLOW_COPY_AND_ASSIGN(LinuxTcpTransport);
};

LinuxTcpTransport::~LinuxTcpTransport()
{
    Close();
}

ssize_t LinuxTcpTransport::Write(const void* data, size_t len)
{
    char tcp_packet_header[HEADER_LEN + 1];
    const char* char_data = reinterpret_cast<const char*>(data);
    size_t count = 0;
    int n;

    /* Compose header */
    snprintf(tcp_packet_header, HEADER_LEN + 1, "FB:%08zx:", len);

    do {
        n = TEMP_FAILURE_RETRY(write(sockfd_, tcp_packet_header + count, HEADER_LEN - count));
        if (n < 0)
            return -1;
        count += n;
    } while (count < HEADER_LEN);

    count = 0;
    do {
        n = TEMP_FAILURE_RETRY(write(sockfd_, char_data + count, len - count));
        if (n < 0)
            return -1;
        count += n;
    } while (count < len);

    return len;
}

ssize_t LinuxTcpTransport::Read(void *data, size_t len)
{
    char* char_data = reinterpret_cast<char*>(data);
    char tcp_packet_header[HEADER_LEN];
    size_t count = 0, fb_payload_len;
    int n;

    /* Read header */
    do {
        n = TEMP_FAILURE_RETRY(read(sockfd_, tcp_packet_header + count, HEADER_LEN - count));
        if (n <= 0)
            return -1;
        count += n;
    } while (count < HEADER_LEN);

    /* Check FastBoot-over-TCP header and get FastBoot payload length */
    if (sscanf(tcp_packet_header, "FB:%08zx:", &fb_payload_len) != 1)
        return -1;

    if (fb_payload_len > len) {
        fprintf(stderr, "Storage length(%zd) is less than received FB packet length(%zd).\n",
                len, fb_payload_len);
        return -1;
    }

    /* Read FastBoot payload */
    count = 0;
    do {
        n = TEMP_FAILURE_RETRY(read(sockfd_, char_data + count, fb_payload_len - count));
        if (n <= 0)
            return -1;
        count += n;
    } while (count < fb_payload_len);

    return fb_payload_len;
}

int LinuxTcpTransport::Close()
{
    int rc = 0;

    if (sockfd_ != -1) {
        rc = TEMP_FAILURE_RETRY(close(sockfd_));
        sockfd_ = -1;
    }
    return rc;
}

Transport *tcp_open(const char *host)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "ERROR: Can't open socket: %s\n", strerror(errno));
        return nullptr;
    }

    struct hostent *server = gethostbyname(host);
    if (server == NULL) {
        fprintf(stderr, "ERROR: Can't find '%s': %s\n", host, hstrerror(h_errno));
        return nullptr;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, sizeof(serv_addr), 0);
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr,
           server->h_addr,
           server->h_length);
    serv_addr.sin_port = htons(1234);
    if (connect(sockfd, (struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) {
        fprintf(stderr, "ERROR: Unable to connect to %s: %s\n",
                host, strerror(errno));
        return nullptr;
    }

    return new LinuxTcpTransport(sockfd);
}

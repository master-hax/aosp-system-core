/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "spiproxyd"

#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <log/log.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <trusty/tipc.h>
#include <unistd.h>

#define SPI_PROXY_PORT "com.android.trusty.spi.proxy"

#define MSG_BUF_SIZE 4096

#define countof(arr) (sizeof(arr) / sizeof(arr[0]))

/* Must be kept in sync with spi/host/interface.h in Trusty */
struct spi_host_msg_hdr {
    uint32_t frag_type;
    uint32_t frag_len;
    uint32_t msg_type;
    uint32_t msg_len;
    uint32_t offset;
};

static int read_msg(int fd, struct spi_host_msg_hdr* hdr, void* msg, size_t len) {
    int rc;
    struct iovec iov[] = {
            {
                    .iov_base = hdr,
                    .iov_len = sizeof(*hdr),
            },
            {
                    .iov_base = msg,
                    .iov_len = len,
            },
    };

    rc = readv(fd, iov, countof(iov));
    if (rc < 0) {
        return rc;
    }

    if ((size_t)rc != sizeof(*hdr) + hdr->frag_len) {
        return -1;
    }

    return 0;
}

static int write_msg(int fd, struct spi_host_msg_hdr* hdr, void* msg, size_t len) {
    int rc;
    struct iovec iov[] = {
            {
                    .iov_base = hdr,
                    .iov_len = sizeof(*hdr),
            },
            {
                    .iov_base = msg,
                    .iov_len = len,
            },
    };

    rc = writev(fd, iov, countof(iov));
    if (rc < 0) {
        return rc;
    }

    if ((size_t)rc != sizeof(*hdr) + hdr->frag_len) {
        return -1;
    }

    return 0;
}

int handle_msg(int trusty_dev_fd, int spi_dev_fd) {
    int rc;
    struct spi_host_msg_hdr hdr;
    uint8_t msg_buf[MSG_BUF_SIZE];

    /* read request from SPI Trusty app */
    rc = read_msg(trusty_dev_fd, &hdr, &msg_buf, MSG_BUF_SIZE);
    if (rc < 0) {
        ALOGE("failed (%d) to read request from TA, message length: %u\n", rc, hdr.frag_len);
        return rc;
    }

    /* forward request to SPI host device */
    rc = write_msg(spi_dev_fd, &hdr, &msg_buf, hdr.frag_len);
    if (rc < 0) {
        ALOGE("failed (%d) to forward request to host, message length: %u\n", rc, hdr.frag_len);
        return rc;
    }

    /* read response from SPI host device */
    rc = read_msg(spi_dev_fd, &hdr, &msg_buf, MSG_BUF_SIZE);
    if (rc < 0) {
        ALOGE("failed (%d) to read response from host, message length: %u\n", rc, hdr.frag_len);
        return rc;
    }

    /* forward response to SPI Trusty app */
    rc = write_msg(trusty_dev_fd, &hdr, &msg_buf, hdr.frag_len);
    if (rc < 0) {
        ALOGE("failed (%d) to forward response to TA, message length: %u\n", rc, hdr.frag_len);
        return rc;
    }

    return 0;
}

int event_loop(int trusty_dev_fd, int spi_dev_fd) {
    while (true) {
        int rc = handle_msg(trusty_dev_fd, spi_dev_fd);
        if (rc < 0) {
            ALOGE("exiting event loop\n");
            return rc;
        }
    }
}

static void show_usage() {
    ALOGE("usage: spiproxyd -t TRUSTY_DEVICE -s SPI_DEVICE\n");
}

static void parse_args(int argc, char* argv[], const char** trusty_dev_name,
                       const char** spi_dev_name) {
    int opt;
    while ((opt = getopt(argc, argv, "ht:s:")) != -1) {
        switch (opt) {
            case 'h':
                show_usage();
                exit(EXIT_SUCCESS);
                break;
            case 't':
                *trusty_dev_name = strdup(optarg);
                break;
            case 's':
                *spi_dev_name = strdup(optarg);
                break;
            default:
                show_usage();
                exit(EXIT_FAILURE);
                break;
        }
    }
}

int main(int argc, char* argv[]) {
    int rc;
    const char* trusty_dev_name;
    const char* spi_dev_name;
    int trusty_dev_fd;
    int spi_dev_fd;

    parse_args(argc, argv, &trusty_dev_name, &spi_dev_name);

    assert(trusty_dev_name);
    assert(spi_dev_name);

    rc = tipc_connect(trusty_dev_name, SPI_PROXY_PORT);
    if (rc < 0) {
        ALOGE("failed (%d) to connect to SPI proxy port\n", rc);
        return rc;
    }
    trusty_dev_fd = rc;

    rc = open(spi_dev_name, O_RDWR, 0);
    if (rc < 0) {
        ALOGE("failed (%d) to open SPI device\n", rc);
        return rc;
    }
    spi_dev_fd = rc;

    return event_loop(trusty_dev_fd, spi_dev_fd);
}

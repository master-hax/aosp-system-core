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

#define LOG_TAG "spi_proxy"

#include <assert.h>
#include <fcntl.h>
#include <log/log.h>
#include <sys/uio.h>
#include <trusty/tipc.h>

#include "proxy.h"

#define countof(arr) (sizeof(arr) / sizeof(arr[0]))

namespace android {
namespace trusty {
namespace spi {

struct spi_host_msg_hdr {
    uint32_t type;
    uint32_t frag_len;
    uint32_t msg_len;
    uint32_t offset;
};

static inline int ReadMsg(int fd, void* hdr, size_t hdr_len, void* msg, size_t msg_len) {
    iovec iov[] = {
            {
                    .iov_base = hdr,
                    .iov_len = hdr_len,
            },
            {
                    .iov_base = msg,
                    .iov_len = msg_len,
            },
    };
    return readv(fd, iov, countof(iov));
}

static inline int WriteMsg(int fd, void* hdr, size_t hdr_len, void* msg, size_t msg_len) {
    iovec iov[] = {
            {
                    .iov_base = hdr,
                    .iov_len = hdr_len,
            },
            {
                    .iov_base = msg,
                    .iov_len = msg_len,
            },
    };
    return writev(fd, iov, countof(iov));
}

SpiProxy::SpiProxy(const char* trusty_dev_name, const char* spi_dev_name,
                   const char* spi_proxy_port)
    : trusty_dev_name_(trusty_dev_name),
      spi_dev_name_(spi_dev_name),
      spi_proxy_port_(spi_proxy_port) {}

SpiProxy::~SpiProxy() {
    tipc_close(trusty_dev_fd_);
    close(spi_dev_fd_);
}

int SpiProxy::Init() {
    int rc = tipc_connect(trusty_dev_name_, spi_proxy_port_);
    if (rc < 0) {
        ALOGE("failed (%d) to connect to SPI proxy port\n", rc);
        return rc;
    }
    trusty_dev_fd_ = rc;

    rc = open(spi_dev_name_, O_RDWR, 0);
    if (rc < 0) {
        ALOGE("failed (%d) to open SPI device\n", rc);
        return rc;
    }
    spi_dev_fd_ = rc;

    return 0;
}

int SpiProxy::HandleMsg() {
    int rc;
    struct spi_host_msg_hdr hdr;
    size_t hdr_len = sizeof(hdr);

    /* read request from SPI Trusty app */
    rc = ReadMsg(trusty_dev_fd_, &hdr, hdr_len, &msg_buf, MSG_BUF_SIZE);
    if (rc < 0 || (size_t)rc != hdr_len + hdr.frag_len) {
        goto err;
    }

    /* forward request to SPI host device */
    rc = WriteMsg(spi_dev_fd_, &hdr, hdr_len, &msg_buf, hdr.frag_len);
    if (rc < 0 || (size_t)rc != hdr_len + hdr.frag_len) {
        goto err;
    }

    /* read response from SPI host device */
    rc = ReadMsg(spi_dev_fd_, &hdr, hdr_len, &msg_buf, MSG_BUF_SIZE);
    if (rc < 0 || (size_t)rc != hdr_len + hdr.frag_len) {
        goto err;
    }

    /* forward response to SPI Trusty app */
    rc = WriteMsg(trusty_dev_fd_, &hdr, hdr_len, &msg_buf, hdr.frag_len);
    if (rc < 0 || (size_t)rc != hdr_len + hdr.frag_len) {
        goto err;
    }

    return 0;

err:
    ALOGE("failed (%d) to handle message of length %u\n", rc, hdr.frag_len);
    if (rc > 0) {
        /* wrong length error case */
        rc = -1;
    }
    return rc;
}

int SpiProxy::StartEventLoop() {
    while (true) {
        int rc = HandleMsg();
        if (rc < 0) {
            ALOGE("exiting event loop\n");
            return rc;
        }
    }
}

}  // namespace spi
}  // namespace trusty
}  // namespace android

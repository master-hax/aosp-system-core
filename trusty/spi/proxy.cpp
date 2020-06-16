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
#include <trusty/tipc.h>

#include "proxy.h"

#define MSG_BUF_SIZE 1024

namespace android {
namespace trusty {
namespace spi {

/**
 * struct spi_host_msg_hdr - header for messages sent to SPI host device
 * @len: total number of bytes sent contained in the message
 */
struct spi_host_msg_hdr {
    uint32_t len;
};

static uint8_t msg_buf[MSG_BUF_SIZE];

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

static int ReadMsg(int fd, void* hdr, size_t hdr_sz, void* msg, size_t msg_sz) {
    int rc;
    int total_sz = 0;

    rc = read(fd, &hdr, hdr_sz);
    if (rc < 0) {
        return rc;
    }
    total_sz += rc;

    rc = read(fd, &msg, msg_sz);
    if (rc < 0) {
        return rc;
    }
    total_sz += rc;

    return rc;
}

static int WriteMsg(int fd, void* hdr, size_t hdr_sz, void* msg, size_t msg_sz) {
    int rc;
    int total_sz = 0;

    rc = write(fd, &hdr, hdr_sz);
    if (rc < 0) {
        return rc;
    }
    total_sz += rc;

    rc = write(fd, &msg, msg_sz);
    if (rc < 0) {
        return rc;
    }
    total_sz += rc;

    return rc;
}

int SpiProxy::HandleMsg() {
    int rc;
    struct spi_host_msg_hdr hdr;
    size_t hdr_sz = sizeof(hdr);

    /* read request from SPI Trusty app */
    rc = ReadMsg(trusty_dev_fd_, &hdr, hdr_sz, &msg_buf, MSG_BUF_SIZE);
    if (rc < 0 || (size_t)rc != hdr_sz + hdr.len) {
        goto err;
    }

    /* forward request to SPI host device */
    rc = WriteMsg(spi_dev_fd_, &hdr, hdr_sz, &msg_buf, hdr.len);
    if (rc < 0 || (size_t)rc != hdr_sz + hdr.len) {
        goto err;
    }

    /* read response from SPI host device */
    rc = ReadMsg(spi_dev_fd_, &hdr, hdr_sz, &msg_buf, MSG_BUF_SIZE);
    if (rc < 0 || (size_t)rc != hdr_sz + hdr.len) {
        goto err;
    }

    /* forward response to SPI Trusty app */
    rc = WriteMsg(trusty_dev_fd_, &hdr, hdr_sz, &msg_buf, hdr.len);
    if (rc < 0 || (size_t)rc != hdr_sz + hdr.len) {
        goto err;
    }

    return 0;

err:
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
            ALOGE("failed (%d) to handle message, exiting event loop\n", rc);
        }
    }
}

}  // namespace spi
}  // namespace trusty
}  // namespace android

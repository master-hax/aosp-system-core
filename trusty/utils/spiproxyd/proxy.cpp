/*
 * Copyright (C) 2020 The Android Open Sourete Project
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

#include <fcntl.h>
#include <sys/uio.h>
#include <trusty/tipc.h>
#include <unistd.h>

#include <android-base/logging.h>

#include "proxy.h"

#define countof(arr) (sizeof(arr) / sizeof(arr[0]))

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;
using std::string;

namespace android {
namespace trusty {
namespace spi {

SpiProxy::SpiProxy(string trusty_dev_name, string spi_dev_name, string spi_proxy_port)
    : trusty_dev_name_(std::move(trusty_dev_name)),
      spi_dev_name_(std::move(spi_dev_name)),
      spi_proxy_port_(std::move(spi_proxy_port)),
      msg_buf_() {}

SpiProxy::~SpiProxy() {
    tipc_close(trusty_dev_fd_);
    close(spi_dev_fd_);
}

Result<void> SpiProxy::Init() {
    int ret = tipc_connect(trusty_dev_name_.c_str(), spi_proxy_port_.c_str());
    if (ret < 0) {
        return ErrnoError() << "failed to connect to SPI proxy port: " << ret;
    }
    trusty_dev_fd_ = ret;

    ret = open(spi_dev_name_.c_str(), O_RDWR, 0);
    if (ret < 0) {
        return ErrnoError() << "failed to open SPI device" << ret;
    }
    spi_dev_fd_ = ret;

    return {};
}

Result<void> SpiProxy::ReadMsg(int fd, spi_host_msg_hdr* hdr) {
    iovec iov[] = {
            {
                    .iov_base = hdr,
                    .iov_len = sizeof(*hdr),
            },
            {
                    .iov_base = msg_buf_.data(),
                    .iov_len = msg_buf_.size(),
            },
    };

    int ret = readv(fd, iov, countof(iov));
    if (ret < 0) {
        return ErrnoError() << "failed to read SPI message: " << ret;
    }

    if (ret != sizeof(*hdr) + hdr->frag_len) {
        return Error() << "SPI message bad length: " << ret;
    }

    return {};
}

Result<void> SpiProxy::WriteMsg(int fd, spi_host_msg_hdr* hdr, size_t len) {
    iovec iov[] = {
            {
                    .iov_base = hdr,
                    .iov_len = sizeof(*hdr),
            },
            {
                    .iov_base = msg_buf_.data(),
                    .iov_len = len,
            },
    };

    int ret = writev(fd, iov, countof(iov));
    if (ret < 0) {
        return ErrnoError() << "failed to write SPI message: " << ret;
    }

    if (ret != sizeof(*hdr) + hdr->frag_len) {
        return Error() << "SPI message bad length: " << ret;
    }

    return {};
}

Result<void> SpiProxy::HandleMsg() {
    spi_host_msg_hdr hdr;

    /* read request from SPI Trusty app */
    auto ret = ReadMsg(trusty_dev_fd_, &hdr);
    if (!ret.ok()) {
        return Error() << "failed to read request from Trusty app: " << ret.error();
    }

    /* forward request to SPI host device */
    ret = WriteMsg(spi_dev_fd_, &hdr, hdr.frag_len);
    if (!ret.ok()) {
        return Error() << "failed to forward request to host device: " << ret.error();
    }

    /* read response from SPI host device */
    ret = ReadMsg(spi_dev_fd_, &hdr);
    if (!ret.ok()) {
        return Error() << "failed to read response from host device: " << ret.error();
    }

    /* forward response to SPI Trusty app */
    ret = WriteMsg(trusty_dev_fd_, &hdr, hdr.frag_len);
    if (!ret.ok()) {
        return Error() << "failed to forward response to Trusty app: " << ret.error();
    }

    return {};
}

Result<void> SpiProxy::StartEventLoop() {
    while (true) {
        Result<void> ret = HandleMsg();
        if (!ret.ok()) {
            return Error() << "exiting event loop: " << ret.error();
        }
    }
}

}  // namespace spi
}  // namespace trusty
}  // namespace android

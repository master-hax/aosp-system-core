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

#pragma once

#include <array>
#include <string>

#include <android-base/result.h>

namespace android {
namespace trusty {
namespace spi {

struct spi_host_msg_hdr {
    uint32_t frag_type;
    uint32_t frag_len;
    uint32_t msg_type;
    uint32_t msg_len;
    uint32_t offset;
};

class SpiProxy {
  public:
    SpiProxy(std::string trusty_dev_name, std::string spi_dev_name, std::string spi_proxy_port);
    ~SpiProxy();

    android::base::Result<void> Init();
    android::base::Result<void> StartEventLoop();

  private:
    android::base::Result<void> ReadMsg(int fd, spi_host_msg_hdr* hdr);
    android::base::Result<void> WriteMsg(int fd, spi_host_msg_hdr* hdr, size_t len);
    android::base::Result<void> HandleMsg();

    std::string trusty_dev_name_;
    std::string spi_dev_name_;
    std::string spi_proxy_port_;

    int trusty_dev_fd_;
    int spi_dev_fd_;

    std::array<uint8_t, 4096> msg_buf_;
};

}  // namespace spi
}  // namespace trusty
}  // namespace android

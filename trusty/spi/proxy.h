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

namespace android {
namespace trusty {
namespace spi {

#define MSG_BUF_SIZE 4096

class SpiProxy {
  public:
    SpiProxy(const char* trusty_dev_name, const char* spi_dev_name, const char* spi_proxy_port);
    ~SpiProxy();

    int Init();
    int StartEventLoop();

  private:
    int HandleMsg();

    const char* trusty_dev_name_;
    const char* spi_dev_name_;
    const char* spi_proxy_port_;

    int trusty_dev_fd_;
    int spi_dev_fd_;

    uint8_t msg_buf[MSG_BUF_SIZE];
};

}  // namespace spi
}  // namespace trusty
}  // namespace android

/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef _INIT_NATIVEZYGOTE_CLIENT_H
#define _INIT_NATIVEZYGOTE_CLIENT_H

#include <android-base/unique_fd.h>
#include <sys/types.h>
#include <unistd.h>

#include "nativezygote.h"
#include "result.h"

namespace android {
namespace init {

class NativeZygoteClient {
  public:
    explicit NativeZygoteClient(const char* socket_name) : socket_name_(socket_name) {}

    Result<pid_t> SendRequest(NativeZygoteRequest const& req);

  private:
    bool EnsureSocketOpen();
    void CloseSocket();

    std::string const socket_name_;
    android::base::unique_fd socket_;
};

}  // namespace init
}  // namespace android

#endif

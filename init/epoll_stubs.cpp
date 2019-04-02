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

// first stage init do nothing epoll stub

#include "epoll.h"

#include <inttypes.h>

#include <chrono>
#include <functional>
#include <thread>

#include "result.h"

namespace android {
namespace init {

Result<Success> Epoll::RegisterHandler(int, std::function<void()>, uint32_t) {
    return Error() << "Epoll not supported in first stage init";
}

Result<Success> Epoll::UnregisterHandler(int) {
    return Error() << "Epoll not supported in first stage init";
}

}  // namespace init
}  // namespace android

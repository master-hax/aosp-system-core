/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <android-base/result.h>

namespace android {
namespace init {

// A FIFO for inter-process communication that uses a Unix pipe internally.
class InterprocessFifo {
  public:
    template <typename T>
    using Result = ::android::base::Result<T>;

    InterprocessFifo();
    InterprocessFifo(const InterprocessFifo& orig) = delete;
    InterprocessFifo(InterprocessFifo&& orig);
    InterprocessFifo& operator=(const InterprocessFifo& orig) = delete;
    InterprocessFifo& operator=(InterprocessFifo&& orig) = delete;
    ~InterprocessFifo();
    void Close();
    Result<void> Initialize();
    Result<void> Write(uint8_t byte);
    Result<uint8_t> Read();

  private:
    std::array<int, 2> fds_;
};

}  // namespace init
}  // namespace android

/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef _INIT_COLDBOOT_H_
#define _INIT_COLDBOOT_H_

#include <functional>
#include <thread>
#include <vector>

#include <android-base/chrono_utils.h>

#include "uevent.h"
#include "uevent_listener.h"

namespace android {
namespace init {

class ColdBoot {
  public:
    ColdBoot(UeventListener& uevent_listener, unsigned int num_threads,
             std::function<void(const Uevent&)> uevent_action)
        : uevent_listener_(uevent_listener),
          uevent_action_(uevent_action),
          num_threads_(num_threads) {}

    bool Run();
    void Join();

  private:
    void ThreadFunction() const;

    UeventListener& uevent_listener_;
    std::function<void(const Uevent&)> uevent_action_;
    unsigned int num_threads_;

    std::vector<std::thread> threads_;
    unsigned int thread_poll_socket_;
    android::base::Timer t_;
};

}  // namespace init
}  // namespace android

#endif

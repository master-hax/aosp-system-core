/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef _INIT_UEVENT_LISTENER_H
#define _INIT_UEVENT_LISTENER_H

#include <android-base/unique_fd.h>

#include "uevent.h"

#define UEVENT_MSG_LEN 2048

class UeventListener {
  public:
    UeventListener();

    bool ReadUevent(uevent* uevent);
    int device_fd() const { return device_fd_.get(); }

  private:
    android::base::unique_fd device_fd_;
};

#endif

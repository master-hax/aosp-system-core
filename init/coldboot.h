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

#ifndef _INIT_COLDBOOT_H
#define _INIT_COLDBOOT_H

#include <dirent.h>

#include <functional>

#include "uevent.h"
#include "uevent_handler.h"
#include "uevent_listener.h"

class ColdBooter {
  public:
    enum class Action {
        // coldboot continues without creating the device for the uevent
        kContinue = 0,
        // coldboot continues after creating the device for the uevent
        kCreate,
        // coldboot stops after creating the device for uevent
        kStop,
    };

    using UeventCallback = std::function<Action(uevent* uevent)>;

    ColdBooter(UeventHandler* uevent_handler, UeventListener* uevent_listener);

    Action ColdBootPath(const std::string& path, UeventCallback callback);
    Action ColdBoot(UeventCallback callback);

  private:
    Action HandleUevents(UeventCallback callback);
    Action DoColdBoot(DIR* d, UeventCallback callback);
    UeventHandler* uevent_handler_;
    UeventListener* uevent_listener_;
};

#endif

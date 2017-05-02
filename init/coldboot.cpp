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

#include "coldboot.h"

#include <fcntl.h>

#include <memory>

ColdBooter::ColdBooter(UeventHandler* uevent_handler, UeventListener* uevent_listener)
    : uevent_handler_(uevent_handler), uevent_listener_(uevent_listener) {}

ColdBooter::Action ColdBooter::HandleUevents(UeventCallback callback) {
    uevent uevent;
    Action act = Action::kCreate;
    while (uevent_listener_->ReadUevent(&uevent) && act != Action::kStop) {
        if (callback) {
            act = callback(&uevent);
        }

        if (act != Action::kContinue) {
            uevent_handler_->HandleUevent(&uevent);
        }
    }
    return act;
}

/* ColdBoot walks parts of the /sys tree and pokes the uevent files
** to cause the kernel to regenerate device add events that happened
** before init's device manager was started
**
** We drain any pending events from the netlink socket every time
** we poke another uevent file to make sure we don't overrun the
** socket's buffer.
*/

ColdBooter::Action ColdBooter::DoColdBoot(DIR* d, UeventCallback callback) {
    Action act = Action::kCreate;

    int dfd = dirfd(d);

    int fd = openat(dfd, "uevent", O_WRONLY);
    if (fd >= 0) {
        write(fd, "add\n", 4);
        close(fd);

        act = HandleUevents(callback);

        if (act == Action::kStop) return act;
    }

    dirent* de;
    while (act != Action::kStop && (de = readdir(d))) {
        if (de->d_type != DT_DIR || de->d_name[0] == '.') continue;

        fd = openat(dfd, de->d_name, O_RDONLY | O_DIRECTORY);
        if (fd < 0) continue;

        DIR* d2 = fdopendir(fd);
        if (d2 == 0) {
            close(fd);
        } else {
            act = DoColdBoot(d2, callback);
            closedir(d2);
        }
    }

    // default is always to continue looking for uevents
    return Action::kContinue;
}

ColdBooter::Action ColdBooter::ColdBootPath(const std::string& path, UeventCallback callback) {
    std::unique_ptr<DIR, decltype(&closedir)> d(opendir(path.c_str()), closedir);
    if (d) {
        return DoColdBoot(d.get(), callback);
    }

    return Action::kContinue;
}

ColdBooter::Action ColdBooter::ColdBoot(UeventCallback callback) {
    const char* paths[] = {"/sys/class", "/sys/block", "/sys/devices"};

    for (const auto path : paths) {
        auto act = ColdBootPath(path, callback);
        if (act == Action::kStop) return act;
    }
    return Action::kContinue;
}

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

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <memory>

/* ColdBoot walks parts of the /sys tree and pokes the uevent files
** to cause the kernel to regenerate device add events that happened
** before init's device manager was started
**
** We drain any pending events from the netlink socket every time
** we poke another uevent file to make sure we don't overrun the
** socket's buffer.
*/

static bool ColdBootDir(DIR* d, ColdBootCallback callback) {
    int dfd = dirfd(d);

    int fd = openat(dfd, "uevent", O_WRONLY);
    if (fd >= 0) {
        write(fd, "add\n", 4);
        close(fd);

        if (callback && callback()) {
            return true;
        }
    }

    dirent* de;
    while ((de = readdir(d)) != nullptr) {
        if (de->d_type != DT_DIR || de->d_name[0] == '.') continue;

        fd = openat(dfd, de->d_name, O_RDONLY | O_DIRECTORY);
        if (fd < 0) continue;

        std::unique_ptr<DIR, decltype(&closedir)> d2(fdopendir(fd), closedir);
        if (d2 == 0) {
            close(fd);
        } else {
            if (ColdBootDir(d2.get(), callback)) return true;
        }
    }

    // default is always to continue looking for uevents
    return false;
}

bool ColdBootPath(const std::string& path, ColdBootCallback callback) {
    std::unique_ptr<DIR, decltype(&closedir)> d(opendir(path.c_str()), closedir);
    if (!d) return false;

    return ColdBootDir(d.get(), callback);
}

const char* kColdBootPaths[] = {"/sys/class", "/sys/block", "/sys/devices"};

void ColdBoot(ColdBootCallback callback) {
    for (const auto path : kColdBootPaths) {
        if (ColdBootPath(path, callback)) return;
    }
}

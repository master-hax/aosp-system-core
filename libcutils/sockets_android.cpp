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

#include <cutils/sockets.h>

#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "android_get_control_env.h"

int android_get_control_socket(const char* name) {
    int fd = __android_get_control_from_env(ANDROID_SOCKET_ENV_PREFIX, name);

    if (fd < 0) return fd;

    // Compare to UNIX domain socket name, must match!
    struct sockaddr_un addr;
    socklen_t addrlen = sizeof(addr);
    int ret = getsockname(fd, (struct sockaddr*)&addr, &addrlen);
    if (ret < 0) return -1;

    constexpr char prefix[] = ANDROID_SOCKET_DIR "/";
    constexpr size_t prefix_size = sizeof(prefix) - sizeof('\0');
    if ((strncmp(addr.sun_path, prefix, prefix_size) == 0) &&
        (strcmp(addr.sun_path + prefix_size, name) == 0)) {
        // It is what we think it is
        return fd;
    }
    return -1;
}

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

#include <poll.h>
#include <sys/socket.h>

#include <android-base/logging.h>

namespace android {
namespace init {

void ColdBoot::ThreadFunction() const {
    pollfd ufd[2];
    ufd[0].events = POLLIN;
    ufd[0].fd = uevent_listener_.device_fd();
    ufd[1].events = POLLIN;
    ufd[1].fd = thread_poll_socket_;

    while (true) {
        ufd[0].revents = 0;
        ufd[1].revents = 0;

        int nr = poll(ufd, arraysize(ufd), -1);
        if (nr == 0) return;
        if (nr < 0) {
            PLOG(ERROR) << "poll() of uevent socket failed, continuing";
            continue;
        }

        // If we get POLLIN from thread_poll_socket_, we still want to check if there are any
        // pending uevents and process them if there are.
        Uevent uevent;
        while (uevent_listener_.ReadUevent(&uevent)) {
            uevent_action_(uevent);
        }

        if (ufd[1].revents & POLLIN) {
            return;
        }
    }
}

bool ColdBoot::Run() {
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) == -1) {
        PLOG(ERROR) << "socketpair failed";
        return false;
    }

    thread_poll_socket_ = sockets[0];
    auto thread_stop_socket = sockets[1];

    for (unsigned int i = 0; i < num_threads_; ++i) {
        threads_.emplace_back([this]() { ThreadFunction(); });
    }

    uevent_listener_.RegenerateUevents(nullptr);

    write(thread_stop_socket, "1", 1);
    close(thread_stop_socket);
    return true;
}

void ColdBoot::Join() {
    for (auto& thread : threads_) {
        thread.join();
    }
    close(thread_poll_socket_);
}

}  // namespace init
}  // namespace android

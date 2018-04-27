/*
 * Copyright (C) 2018 The Android Open Source Project
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

// generic default epoll infrastructure

#define LOG_TAG "epollfd"

#include <keychord/keychord.h>

#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <unordered_map>

#include <android-base/logging.h>

#include "getevent.h"

namespace {

int epoll_fd = -1;
std::unordered_map<int, std::pair<std::string, keychord_epoll_handler_fn>> registered_fd;
bool KeychordThreadRunning;
pthread_t KeychordThread;

int _keychord_default_register_epoll_handler(int epoll_fd, keychord_epoll_handler_fn fn, int fd,
                                             const char* name) {
    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = reinterpret_cast<void*>(fn);
    auto ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
    if (ret == -1) {
        PLOG(ERROR) << "EPOLL_CTL_ADD " << name << "(" << fd << ")";
    }
    return ret;
}

}  // namespace

int keychord_default_reset_epoll_fd(int fd) {
    if (epoll_fd == fd) return 0;

    if (epoll_fd >= 0) {
        auto hold = epoll_fd;
        epoll_fd = -1;
        ::close(hold);
    }
    if (fd < 0) return 0;

    int retval = 0;
    for (auto& pair : registered_fd) {
        auto ret = _keychord_default_register_epoll_handler(fd, pair.second.second, pair.first,
                                                            pair.second.first.c_str());
        if (!ret) retval = ret;
    }
    epoll_fd = fd;
    return retval;
}

void keychord_default_clear_epoll() {
    registered_fd.clear();
}

int keychord_default_register_epoll_handler(keychord_epoll_handler_fn fn, int fd, const char* name) {
    if (epoll_fd < 0) {
        epoll_fd = ::epoll_create1(EPOLL_CLOEXEC);
        if (epoll_fd < 0) {
            PLOG(ERROR) << "epoll_create1";
            return epoll_fd;
        }
    }
    auto ret = _keychord_default_register_epoll_handler(epoll_fd, fn, fd, name);
    if (ret != 0) return ret;
    registered_fd.emplace(std::make_pair(fd, std::make_pair(std::string(name), fn)));
    LOG(VERBOSE) << "keychord_default_register_epoll_handler(0x" << std::hex
                 << reinterpret_cast<uintptr_t>(fn) << "," << std::dec << fd << "," << name << ")";
    return 0;
}

int keychord_default_unregister_epoll_handler(int fd, const char* name) {
    auto it = registered_fd.find(fd);
    if (it == registered_fd.end()) {
        PLOG(WARNING) << "keychord_default_unregister_epoll_handler(" << fd << ",\"" << name
                      << "\") not registered";
    } else {
        if ((*it).second.first != name) {
            PLOG(WARNING) << "keychord_default_unregister_epoll_handler(" << fd << ",\"" << name
                          << "\") name does not match registration \"" << (*it).second.first;
        }
        registered_fd.erase(it);
    }
    if (epoll_fd < 0) {
        LOG(ERROR) << "epoll file descriptor not open";
    }
    auto ret = ::epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
    if (ret == -1) {
        PLOG(ERROR) << "EPOLL_CTL_DEL " << name << "(" << fd << ")";
    }
    if (registered_fd.empty() && KeychordIsDefault() && KeychordThreadRunning) {
        keychord_stop();
    }
    LOG(VERBOSE) << "keychord_default_unregister_epoll_handler(" << fd << "," << name << ")";
    return ret;
}

int keychord_default_epoll_wait(int epoll_timeout_ms) {
    if (!KeychordIsDefault()) {
        LOG(ERROR) << "epoll not configured correctly";
        errno = EINVAL;
        return -1;
    }
    if (epoll_fd < 0) {
        LOG(ERROR) << "epoll file descriptor not open";
        errno = EBADF;
        return -1;
    }
    epoll_event ev;
    int ret = ::epoll_wait(epoll_fd, &ev, 1, keychord_timeout_ms(epoll_timeout_ms));
    if (ret == -1) {
        PLOG(ERROR) << "epoll_wait";
    } else if (ret == 1) {
        (*reinterpret_cast<keychord_epoll_handler_fn>(ev.data.ptr))();
    }
    return ret;
}

std::chrono::milliseconds keychord_default_epoll_wait(std::chrono::milliseconds epoll_timeout) {
    int epoll_timeout_ms = -1;
    if (epoll_timeout != std::chrono::milliseconds::max()) {
        epoll_timeout_ms = epoll_timeout.count();
        /* even a ns of duration, round up to a ms */
        if ((epoll_timeout_ms == 0) && (epoll_timeout != std::chrono::milliseconds::zero())) {
            epoll_timeout_ms = 1;
        }
    }
    return std::chrono::milliseconds(keychord_default_epoll_wait(epoll_timeout_ms));
}

// epollfd thread support

namespace {

void* keychordThread(void* obj) {
    auto threadname = static_cast<const char*>(obj);
    if (!threadname) threadname = "epollfd";
    prctl(PR_SET_NAME, threadname);
    LOG(INFO) << threadname << ": started";
    while (KeychordThreadRunning && (epoll_fd >= 0)) {
        epoll_event ev;
        int ret = ::epoll_wait(epoll_fd, &ev, 1, keychord_timeout_ms(-1));
        if (ret < 0) break;
        if (ret == 0) continue;
        (*reinterpret_cast<keychord_epoll_handler_fn>(ev.data.ptr))();
    }
    KeychordThreadRunning = false;
    return nullptr;
}

}  // namespace

int keychord_run(int fd, const char* threadname) {
    if (fd != 0) {
        errno = EBADF;
        return -1;
    }

    if (epoll_fd < 0) {
        LOG(ERROR) << "epoll file descriptor not open";
        errno = EBADF;
        return -1;
    }

    if (!KeychordIsDefault()) {
        LOG(ERROR) << "not setup for default handling";
        errno = EINVAL;
        return -1;
    }

    if (KeychordThreadRunning) {
        return 0;
    }

    pthread_attr_t attr;
    if (pthread_attr_init(&attr)) {
        LOG(ERROR) << "failed to allocate attibutes for epollfd thread";
        errno = ENOMEM;
        return -1;
    }

    sched_param param;
    memset(&param, 0, sizeof(param));
    pthread_attr_setschedparam(&attr, &param);
    pthread_attr_setschedpolicy(&attr, SCHED_BATCH);
    auto ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (ret) {
        pthread_attr_destroy(&attr);
        LOG(ERROR) << "failed to detach epollfd thread";
        return ret;
    }

    KeychordThreadRunning = true;
    ret = pthread_create(&KeychordThread, &attr, keychordThread, const_cast<char*>(threadname));
    pthread_attr_destroy(&attr);

    if (ret) {
        KeychordThreadRunning = false;
        LOG(ERROR) << "failed to spawn epollfd thread";
    }

    return ret;
}

int keychord_stop(int /* fd */) {
    auto hold = epoll_fd;
    epoll_fd = -1;
    ::close(hold);
    if (KeychordThreadRunning) {
        // two seconds maximum wait
        for (auto retry = 200; retry && KeychordThreadRunning; --retry) {
            usleep(10000);
        }
#ifndef __BIONIC__
        if (KeychordThreadRunning) {
            pthread_cancel(KeychordThread);
        }
#endif
        KeychordThreadRunning = false;
    }
    return 0;
}

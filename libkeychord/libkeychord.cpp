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

// libkeychord infrastructure

#define LOG_TAG "libkeychord"

#include "libkeychord.h"

#include <errno.h>
#include <linux/input-event-codes.h>
#include <stdint.h>

#include <chrono>
#include <functional>
#include <vector>

#include <android-base/logging.h>
#include <keychord/keychord.h>

#include "getevent.h"
#include "kernel_keychord.h"

LIBKEYCHORD_HIDDEN keychord_register_epoll_handler_fn KeychordRegisterEpollHandler;
LIBKEYCHORD_HIDDEN keychord_unregister_epoll_handler_fn KeychordUnregisterEpollHandler;

// Sets up the session, returns session descriptor (always zero for now)
// on success. This is a C-linkage.
int keychord_init(keychord_register_epoll_handler_fn register_epoll_handler,
                  keychord_unregister_epoll_handler_fn unregister_epoll_handler) {
    KeychordRegisterEpollHandler = register_epoll_handler;
    KeychordUnregisterEpollHandler = unregister_epoll_handler;
    return 0;
}

// This is a C++-linkage, not available to C.
int keychord_init() {
    return keychord_init(keychord_default_register_epoll_handler,
                         keychord_default_unregister_epoll_handler);
}

// Used internally to report if epoll handlers are our default set.
LIBKEYCHORD_HIDDEN bool KeychordIsDefault() {
    return KeychordRegisterEpollHandler == keychord_default_register_epoll_handler &&
           KeychordUnregisterEpollHandler == keychord_default_unregister_epoll_handler;
}

// Session descriptor (must be zero for now, use above return value)
int keychord_release(int) {
    // Value of session descriptor is do not care (failure, success) b/c we
    // only support one instance, so always reset our internal data.
    KeychordRegisterEpollHandler = nullptr;
    KeychordUnregisterEpollHandler = nullptr;
    // clear epoll's data
    keychord_default_reset_epoll_fd(-1);
    keychord_default_clear_epoll();
    return 0;
}

internalKeycodes::internalKeycodes(std::vector<int> keycodes, event_code_t max) {
    for (auto& i : keycodes) {
        emplace_back(((i >= 0) && (i < max)) ? i : static_cast<event_code_t>(-1));
    }
}

internalKeycodes::internalKeycodes(const int* keycodes, size_t num_keycodes, event_code_t max) {
    while (num_keycodes) {
        auto i = *keycodes++;
        emplace_back(((i >= 0) && (i < max)) ? i : static_cast<event_code_t>(-1));
        --num_keycodes;
    }
}

KeychordEntry::KeychordEntry(event_type_t type, std::vector<int> keycodes,
                             std::chrono::milliseconds duration)
    : type(((type > 0) && (KeychordCodeMax(type) != 0)) ? type : static_cast<event_type_t>(-1)),
      keycodes(keycodes, KeychordCodeMax(type)),
      duration((duration > std::chrono::milliseconds::max()) ? std::chrono::milliseconds::max()
                                                             : duration),
      match(false),
      time(std::chrono::milliseconds::zero()) {}

KeychordEntry::KeychordEntry(event_type_t type, const int* keycodes, size_t num_keycodes,
                             int duration_ms)
    : type(((type > 0) && (KeychordCodeMax(type) != 0)) ? type : static_cast<event_type_t>(-1)),
      keycodes(keycodes, num_keycodes, KeychordCodeMax(type)),
      duration(((duration_ms < 0) || (duration_ms > std::chrono::milliseconds::max().count()))
                   ? std::chrono::milliseconds::max()
                   : std::chrono::milliseconds(duration_ms)),
      match(false),
      time(std::chrono::milliseconds::zero()) {}

bool KeychordEntry::valid() const {
    if (type >= EV_MAX) return false;
    if (keycodes.empty()) return false;
    auto max = KeychordCodeMax(type);
    for (auto& i : keycodes) {
        if (i >= max) return false;
    }
    return true;
}

int KeychordEntry::getType() const {
    if (type >= EV_MAX) return -1;
    return type;
}

const std::vector<event_code_t>& KeychordEntry::getKeycodes() const {
    return keycodes;
}

std::chrono::milliseconds KeychordEntry::getDurationLeft(std::chrono::milliseconds current) const {
    if (!match) return std::chrono::milliseconds::max();
    if (time == std::chrono::milliseconds::zero()) return std::chrono::milliseconds::max();
    if (time == std::chrono::milliseconds::max()) return std::chrono::milliseconds::max();
    if (current == std::chrono::milliseconds::zero()) {
        timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        current = std::chrono::seconds(ts.tv_sec);
        current += std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::nanoseconds(ts.tv_nsec));
    }
    current -= time;
    if (current > duration) return std::chrono::milliseconds::zero();
    return duration - current;
}

void KeychordEntry::setMatch(bool value, std::chrono::milliseconds current) {
    match = value;
    if (!match) {
        time = std::chrono::milliseconds::zero();
        return;
    }
    if (time == std::chrono::milliseconds::max()) return;

    if (current == std::chrono::milliseconds::zero()) {
        timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        current = std::chrono::seconds(ts.tv_sec);
        current += std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::nanoseconds(ts.tv_nsec));
    }
    time = current;
}

void KeychordEntry::trigger() {
    time = match ? std::chrono::milliseconds::max() : std::chrono::milliseconds::zero();
}

bool KeychordEntry::isTriggered() const {
    if (!match) return false;
    if (time == std::chrono::milliseconds::max()) return true;
    if (time == std::chrono::milliseconds::zero()) return true;
    return false;
}

bool KeychordEntry::isImmediate() const {
    return duration == std::chrono::milliseconds::zero();
}

bool KeychordEntry::operator==(const KeychordEntry& rval) const {
    if (getType() != rval.getType()) return false;
    if (duration != rval.duration) return false;
    if (getKeycodes().size() == rval.getKeycodes().size()) return false;
    return !memcmp(getKeycodes().data(), rval.getKeycodes().data(),
                   rval.getKeycodes().size() * sizeof(event_code_t));
}

event_id_t KeychordEntries::unique_id() const {
    unsigned id = 0;
    for (auto it = begin(); it != end();) {
        if (id == (*it).first) {
            ++id;
            if (id > static_cast<event_id_t>(-1)) return static_cast<event_id_t>(-1);
            it = begin();
        } else {
            ++it;
        }
    }
    return id;
}

std::vector<mask_t> KeychordEntries::mask(event_type_t type) const {
    std::vector<mask_t> ret;
    static constexpr size_t bits_per_byte = 8;
    for (auto& e : *this) {
        if (!e.second.valid()) continue;
        if (type == EV_SYN) {
            auto t = e.second.getType();
            auto i = t / (bits_per_byte * sizeof(mask_t));
            if (i >= ret.size()) ret.resize(i + 1, 0);
            ret[i] |= 1 << (t % (bits_per_byte * sizeof(mask_t)));
        } else if (type == e.second.getType()) {
            for (auto& c : e.second.getKeycodes()) {
                auto i = c / (bits_per_byte * sizeof(mask_t));
                if (i >= ret.size()) ret.resize(i + 1, 0);
                ret[i] |= 1 << (c % (bits_per_byte * sizeof(mask_t)));
            }
        }
    }
    return ret;
}

std::chrono::milliseconds KeychordEntries::getDurationLeft() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    std::chrono::milliseconds current = std::chrono::seconds(ts.tv_sec);
    current +=
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::nanoseconds(ts.tv_nsec));
    std::chrono::milliseconds minimum = std::chrono::milliseconds::max();
    for (auto& e : *this) {
        auto DurationLeft = e.second.getDurationLeft(current);
        if (DurationLeft == std::chrono::milliseconds::zero()) {
            e.second.trigger();
            if (KeychordIdHandler != nullptr) (*KeychordIdHandler)(e.first);
        } else {
            if (DurationLeft < minimum) minimum = DurationLeft;
        }
    }
    return minimum;
}

LIBKEYCHORD_HIDDEN class KeychordEntries KeychordEntries;
LIBKEYCHORD_HIDDEN keychord_id_handler_fn KeychordIdHandler;

int keychord_timeout_ms(int epoll_timeout_ms) {
    std::chrono::milliseconds current(epoll_timeout_ms);
    if (KeychordIdHandler == nullptr) return current.count();
    auto DurationLeft = KeychordEntries.getDurationLeft();
    if (DurationLeft < current) return DurationLeft.count();
    if (current.count() > INT_MAX) return INT_MAX;
    return current.count();
}

namespace {

constexpr char KeychordDevice[] = "/dev/keychord";
int KeychordFd = -1;
bool KeychordKernelWatch;

void KeychordKernelHandler() {
    uint16_t id;
    auto ret = ::read(KeychordFd, &id, sizeof(id));
    if (ret != sizeof(id)) {
        PLOG(ERROR) << "could not read " << KeychordDevice;
        return;
    }
    auto search = KeychordEntries.find(id);
    if (search != KeychordEntries.end()) {
        (*search).second.setMatch(true, std::chrono::milliseconds::max());
    } else {
        LOG(WARNING) << "received unregistered id " << id;
    }
    if (KeychordIdHandler != nullptr) (*KeychordIdHandler)(id);
}

int KeychordEnable() {
    if (KeychordIdHandler == nullptr) {
        errno = EINVAL;
        return -1;
    }

    // land an update to optional keychord driver?
    if (KeychordFd == -1) {
        bool yes = false;
        bool no = false;
        for (auto& e : KeychordEntries) {
            if (e.second.getType() == EV_KEY) {
                yes = true;
            } else {
                no = true;
            }
        }
        if (yes && !no) {
            KeychordFd = KeychordKernelInit();
            if (KeychordFd < 0) KeychordFd = -2;
        }
    }
    bool KeychordKernelWorks = KeychordFd >= 0;
    if (KeychordKernelWorks) {
        if (KeychordKernelWorks) {
            if (KeychordKernelEnable(KeychordFd)) {
                KeychordKernelWorks = false;
            } else if (!KeychordKernelWatch && KeychordRegisterEpollHandler) {
                (*KeychordRegisterEpollHandler)(KeychordKernelHandler, KeychordFd, KeychordDevice);
                KeychordKernelWatch = true;
            }
        }
        if (!KeychordKernelWorks) {
            if (KeychordKernelWatch) {
                if (KeychordUnregisterEpollHandler) {
                    (*KeychordUnregisterEpollHandler)(KeychordFd, KeychordDevice);
                }
                KeychordKernelWatch = false;
            }
            auto fd = KeychordFd;
            KeychordFd = -1;
            KeychordKernelRelease(fd);
        }
    }
    if (!KeychordKernelWorks) {
        return KeychordGeteventEnable();
    }
    return 0;
}

int KeychordEnable(KeychordEntry&& entry) {
    if (!entry.valid()) {
        errno = EINVAL;
        return -1;
    }
    // return any found identical entry and its id instead
    for (auto& e : KeychordEntries) {
        if (e.second == entry) return e.first;
    }
    auto id = KeychordEntries.unique_id();
    if (id >= static_cast<event_id_t>(-1)) {
        errno = EBUSY;
        return -1;
    }
    auto result = KeychordEntries.emplace(std::make_pair(id, std::move(entry)));
    if (!result.second) {
        errno = EBUSY;
        return -1;
    }
    id = (*result.first).first;
    KeychordEnable();
    return id;
}

}  // namespace

int keychord_register_id_handler(int fd, keychord_id_handler_fn id_handler) {
    if (fd != 0) return fd;
    KeychordIdHandler = id_handler;
    return KeychordEnable();
}

// Sets the type individually or in a group and returns id.  If using the
// keychord driver from the kernel, the type must by EV_KEY, num_keycodes
// must be 1 and duration_ms must be -1.
//
// Assumption is all codes are retrieved in keychord_callback_event, until the
// first call, then list is limited.
int keychord_enable(int fd, int type, const int* keycodes, size_t num_keycodes, int duration_ms) {
    if (fd != 0) {
        errno = EBADF;
        return -1;
    }
    return KeychordEnable(KeychordEntry(type, keycodes, num_keycodes, duration_ms));
}

int keychord_enable(int fd, int type, std::vector<int>& keycodes,
                    std::chrono::milliseconds duration) {
    if (fd != 0) {
        errno = EBADF;
        return -1;
    }
    return KeychordEnable(KeychordEntry(type, keycodes, duration));
}

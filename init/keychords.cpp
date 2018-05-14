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

#include "keychords.h"

#include <dirent.h>
#include <fcntl.h>
#include <linux/input.h>
#include <sys/cdefs.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/logging.h>

using namespace std::chrono_literals;

namespace android {
namespace init {

Keychords::Keychords() : epoll(nullptr), inotify_fd(-1) {}

Keychords::~Keychords() noexcept {
    if (inotify_fd >= 0) {
        epoll->UnregisterHandler(inotify_fd);
        ::close(inotify_fd);
    }
    while (!registration.empty()) GeteventCloseDevice(registration.begin()->first);
}

Keychords::Mask::Mask(size_t bit) : bits((bit + sizeof(mask_t) - 1) / sizeof(mask_t), 0) {}

void Keychords::Mask::SetBit(size_t bit, bool value) {
    auto idx = bit / (kBitsPerByte * sizeof(mask_t));
    if (idx >= bits.size()) return;
    if (value) {
        bits[idx] |= mask_t(1) << (bit % (kBitsPerByte * sizeof(mask_t)));
    } else {
        bits[idx] &= ~(mask_t(1) << (bit % (kBitsPerByte * sizeof(mask_t))));
    }
}

bool Keychords::Mask::GetBit(size_t bit) const {
    auto idx = bit / (kBitsPerByte * sizeof(mask_t));
    return bits[idx] & (mask_t(1) << (bit % (kBitsPerByte * sizeof(mask_t))));
}

size_t Keychords::Mask::bytesize() const {
    return bits.size() * sizeof(mask_t);
}

void* Keychords::Mask::data() {
    return bits.data();
}

size_t Keychords::Mask::size() const {
    return bits.size() * sizeof(mask_t) * kBitsPerByte;
}

void Keychords::Mask::resize(size_t bit) {
    auto idx = bit / (kBitsPerByte * sizeof(mask_t));
    if (idx >= bits.size()) {
        bits.resize(idx + 1, 0);
    }
}

Keychords::Mask::operator bool() const {
    for (size_t i = 0; i < bits.size(); ++i) {
        if (bits[i]) return true;
    }
    return false;
}

Keychords::Mask Keychords::Mask::operator&(const Keychords::Mask& rval) const {
    auto len = std::min(bits.size(), rval.bits.size());
    Keychords::Mask ret;
    ret.bits.resize(len);
    for (size_t i = 0; i < len; ++i) {
        ret.bits[i] = bits[i] & rval.bits[i];
    }
    return ret;
}

void Keychords::Mask::operator|=(const Keychords::Mask& rval) {
    auto len = rval.bits.size();
    bits.resize(len);
    for (size_t i = 0; i < len; ++i) {
        bits[i] |= rval.bits[i];
    }
}

Keychords::Entry::Entry(std::chrono::milliseconds duration)
    : notified(false), duration(duration), matched(kMatchedOff) {}

void Keychords::LambdaCheck() {
    for (auto& e : entries) {
        auto found = true;
        for (auto& code : e.first) {
            if (code < 0) continue;
            if (!current.GetBit(code)) {
                e.second.notified = false;
                e.second.matched = e.second.kMatchedOff;
                found = false;
                break;
            }
        }
        if (!found) continue;
        if (e.second.notified) continue;
        if (e.second.duration != e.second.kDurationOff) {
            e.second.matched = android::base::boot_clock::now() + e.second.duration;
            continue;
        }
        e.second.notified = true;
        std::invoke(handler, e.first);
    }
}

void Keychords::LambdaHandler(int fd) {
    input_event event;
    auto res = TEMP_FAILURE_RETRY(::read(fd, &event, sizeof(event)));
    if ((res != sizeof(event)) || (event.type != EV_KEY)) return;
    current.SetBit(event.code, event.value);
    LambdaCheck();
}

bool Keychords::GeteventEnable(int fd) {
    // Make sure it is an event channel, should pass this ioctl call
    int version;
    if (::ioctl(fd, EVIOCGVERSION, &version)) return false;

#ifdef EVIOCSMASK
    static auto EviocsmaskSupported = true;
    if (EviocsmaskSupported) {
        Keychords::Mask mask(EV_KEY);
        mask.SetBit(EV_KEY);
        input_mask msg = {};
        msg.type = EV_SYN;
        msg.codes_size = mask.bytesize();
        msg.codes_ptr = reinterpret_cast<uintptr_t>(mask.data());
        if (::ioctl(fd, EVIOCSMASK, &msg) == -1) {
            PLOG(WARNING) << "EVIOCSMASK not supported";
            EviocsmaskSupported = false;
        }
    }
#endif

    Keychords::Mask mask;
    for (auto& e : entries) {
        for (auto& code : e.first) {
            if (code < 0) continue;
            mask.resize(code);
            mask.SetBit(code);
        }
    }

    current.resize(mask.size());
    Keychords::Mask available(mask.size());
    auto res = ::ioctl(fd, EVIOCGBIT(EV_KEY, available.bytesize()), available.data());
    if (res == -1) return false;
    if (!(available & mask)) return false;

#ifdef EVIOCSMASK
    if (EviocsmaskSupported) {
        input_mask msg = {};
        msg.type = EV_KEY;
        msg.codes_size = mask.bytesize();
        msg.codes_ptr = reinterpret_cast<uintptr_t>(mask.data());
        ::ioctl(fd, EVIOCSMASK, &msg);
    }
#endif

    Keychords::Mask set(mask.size());
    res = ::ioctl(fd, EVIOCGKEY(res), set.data());
    if (res > 0) {
        current |= mask & available & set;
        LambdaCheck();
    }
    epoll->RegisterHandler(fd, [this, fd]() { this->LambdaHandler(fd); });
    return true;
}

void Keychords::GeteventOpenDevice(const std::string& device) {
    if (registration.count(device)) return;
    auto fd = TEMP_FAILURE_RETRY(::open(device.c_str(), O_RDWR | O_CLOEXEC));
    if (fd == -1) {
        PLOG(ERROR) << "Can not open " << device;
        return;
    }
    if (!GeteventEnable(fd)) {
        ::close(fd);
    } else {
        registration.emplace(device, fd);
    }
}

void Keychords::GeteventCloseDevice(const std::string& device) {
    auto it = registration.find(device);
    if (it == registration.end()) return;
    auto fd = (*it).second;
    epoll->UnregisterHandler(fd);
    registration.erase(it);
    ::close(fd);
}

void Keychords::InotifyHandler() {
    unsigned char buf[512];  // History shows 32-64 bytes typical

    auto res = TEMP_FAILURE_RETRY(::read(inotify_fd, buf, sizeof(buf)));
    if (res < 0) {
        PLOG(WARNING) << "could not get event";
        return;
    }

    auto event_buf = buf;
    while (static_cast<size_t>(res) >= sizeof(inotify_event)) {
        auto event = reinterpret_cast<inotify_event*>(event_buf);
        auto event_size = sizeof(inotify_event) + event->len;
        if (static_cast<size_t>(res) < event_size) break;
        if (event->len) {
            std::string devname(kDevicePath);
            devname += '/';
            devname += event->name;
            if (event->mask & IN_CREATE) {
                GeteventOpenDevice(devname);
            } else {
                GeteventCloseDevice(devname);
            }
        }
        res -= event_size;
        event_buf += event_size;
    }
}

void Keychords::GeteventOpenDevice() {
    inotify_fd = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (inotify_fd < 0) {
        PLOG(WARNING) << "Could not instantiate inotify for " << kDevicePath;
    } else if (::inotify_add_watch(inotify_fd, kDevicePath, IN_DELETE | IN_CREATE | IN_ONLYDIR) < 0) {
        PLOG(WARNING) << "Could not add watch for " << kDevicePath;
        ::close(inotify_fd);
        inotify_fd = -1;
    }

    std::unique_ptr<DIR, decltype(&closedir)> device(opendir(kDevicePath), closedir);
    if (device) {
        dirent* entry;
        while ((entry = readdir(device.get()))) {
            if (entry->d_name[0] == '.') continue;
            std::string devname(kDevicePath);
            devname += '/';
            devname += entry->d_name;
            GeteventOpenDevice(devname);
        }
    }

    if (inotify_fd >= 0) epoll->RegisterHandler(inotify_fd, [this]() { this->InotifyHandler(); });
}

void Keychords::Register(const std::set<int>& keycodes) {
    if (keycodes.empty()) return;
    auto code = *keycodes.begin();
    auto duration = (code < 0) ? std::chrono::milliseconds(-code) : Entry::Entry::kDurationOff;
    entries.try_emplace(keycodes, Entry(duration));
}

void Keychords::Start(Epoll* init_epoll, std::function<void(const std::set<int>&)> init_handler) {
    epoll = init_epoll;
    handler = init_handler;
    if (entries.size()) GeteventOpenDevice();
}

std::optional<std::chrono::milliseconds> Keychords::Wait(
    std::optional<std::chrono::milliseconds> wait) {
    if (entries.empty()) return wait;

    android::base::boot_clock::time_point now = Entry::Entry::kMatchedOff;
    for (auto& e : entries) {
        if (e.second.notified || (e.second.duration == e.second.kDurationOff) ||
            (e.second.matched == e.second.kMatchedOff))
            continue;
        if (now == e.second.kMatchedOff) now = android::base::boot_clock::now();
        if (e.second.matched > now) {
            auto duration =
                std::chrono::duration_cast<std::chrono::milliseconds>(e.second.matched - now);
            if (!wait || (wait > duration)) wait = duration;
            continue;
        }
        e.second.matched = e.second.kMatchedOff;
        e.second.notified = true;
        std::invoke(handler, e.first);
    }
    return wait;
}

}  // namespace init
}  // namespace android

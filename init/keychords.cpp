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
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <android-base/logging.h>
#include <android-base/properties.h>

#include "init.h"

typedef unsigned char event_id_t;
typedef unsigned int mask_t;
constexpr size_t bits_per_byte = 8;

namespace android {
namespace init {

namespace {

event_id_t keychords_count;

struct KeychordEntry {
    const std::vector<int> keycodes;
    bool notified;
    event_id_t id;

    KeychordEntry(const std::vector<int>& keycodes)
        : keycodes(keycodes), notified(false), id(keychords_count + 1) {}
};

std::vector<KeychordEntry> KeychordEntries;
std::vector<mask_t> KeychordCurrent;

std::map<std::string, int> KeychordRegistration;

constexpr char DevicePath[] = "/dev/input";

void handle_keychord(int id) {
    // Only handle keychords if adb is enabled.
    std::string adb_enabled = android::base::GetProperty("init.svc.adbd", "");
    if (adb_enabled == "running") {
        Service* svc = ServiceList::GetInstance().FindService(id, &Service::keychord_id);
        if (svc) {
            LOG(INFO) << "Starting service '" << svc->name() << "' from keychord " << id;
            if (auto result = svc->Start(); !result) {
                LOG(ERROR) << "Could not start service '" << svc->name() << "' from keychord " << id
                           << ": " << result.error();
            }
        } else {
            LOG(ERROR) << "Service for keychord " << id << " not found";
        }
    } else {
        LOG(WARNING) << "Not starting service for keychord " << id << " because ADB is disabled";
    }
}

void KeychordLambdaCheck() {
    for (auto& e : KeychordEntries) {
        bool found = true;
        for (auto& code : e.keycodes) {
            auto idx = code / (bits_per_byte * sizeof(mask_t));
            if (!(KeychordCurrent[idx] & (mask_t(1) << (code % (bits_per_byte * sizeof(mask_t)))))) {
                e.notified = false;
                found = false;
                break;
            }
        }
        if (!found) continue;
        if (e.notified) continue;
        e.notified = true;
        handle_keychord(e.id);
    }
}

void KeychordLambdaHandler(int fd) {
    input_event event;
    auto res = TEMP_FAILURE_RETRY(::read(fd, &event, sizeof(event)));
    if ((res != sizeof(event)) || (event.type != EV_KEY)) return;
    auto idx = event.code / (bits_per_byte * sizeof(mask_t));
    if (idx >= KeychordCurrent.size()) return;
    if (event.value) {
        KeychordCurrent[idx] |= mask_t(1) << (event.code % (bits_per_byte * sizeof(mask_t)));
    } else {
        KeychordCurrent[idx] &= ~(mask_t(1) << (event.code % (bits_per_byte * sizeof(mask_t))));
    }
    KeychordLambdaCheck();
}

void SetBit(std::vector<mask_t>& bits, size_t bit) {
    auto idx = bit / (bits_per_byte * sizeof(mask_t));
    if (idx >= bits.size()) {
        bits.resize(idx + 1, 0);
    }
    bits[idx] |= mask_t(1) << (bit % (bits_per_byte * sizeof(mask_t)));
}

bool KeychordGeteventEnable(int fd) {
    static bool EviocsmaskSupported = true;

    // Make sure it is an event channel, should pass this ioctl call
    int version;
    if (::ioctl(fd, EVIOCGVERSION, &version)) return false;

    if (EviocsmaskSupported) {
        std::vector<mask_t> mask;
        SetBit(mask, EV_KEY);
        input_mask msg = {};
        msg.type = EV_SYN;
        msg.codes_size = mask.size() * sizeof(mask_t);
        msg.codes_ptr = reinterpret_cast<uintptr_t>(mask.data());
        if (::ioctl(fd, EVIOCSMASK, &msg) == -1) {
            PLOG(WARNING) << "EVIOCSMASK not supported";
            EviocsmaskSupported = false;
        }
    }

    std::vector<mask_t> mask;
    for (auto& e : KeychordEntries) {
        for (auto& code : e.keycodes) {
            SetBit(mask, code);
        }
    }

    KeychordCurrent.resize(mask.size(), 0);
    std::vector<mask_t> available(mask.size(), 0);
    auto res = ::ioctl(fd, EVIOCGBIT(EV_KEY, available.size() * sizeof(mask_t)), available.data());
    if (res == -1) return false;
    bool something = false;
    size_t len = std::min((size_t(res) + sizeof(mask_t) - 1) / sizeof(mask_t), mask.size());
    for (size_t i = 0; i < len; ++i) {
        if (available[i] & mask[i]) {
            something = true;
            break;
        }
    }
    if (!something) return false;

    if (EviocsmaskSupported) {
        input_mask msg = {};
        msg.type = EV_KEY;
        msg.codes_size = mask.size() * sizeof(mask_t);
        msg.codes_ptr = reinterpret_cast<uintptr_t>(mask.data());
        ::ioctl(fd, EVIOCSMASK, &msg);
    }

    std::vector<mask_t> set(mask.size(), 0);
    res = ::ioctl(fd, EVIOCGKEY(res), set.data());
    if (res > 0) {
        len = std::min((size_t(res) + sizeof(mask_t) - 1) / sizeof(mask_t), mask.size());
        for (size_t i = 0; i < len; ++i) {
            KeychordCurrent[i] |= mask[i] & available[i] & set[i];
        }
        KeychordLambdaCheck();
    }
    register_epoll_handler(fd, [fd]() { KeychordLambdaHandler(fd); });
    return true;
}

void GeteventOpenDevice(std::string& device) {
    if (KeychordRegistration.find(device) != KeychordRegistration.end()) return;
    auto fd = TEMP_FAILURE_RETRY(::open(device.c_str(), O_RDWR | O_CLOEXEC));
    if (fd == -1) {
        PLOG(ERROR) << "Can not open " << device;
        return;
    }
    if (!KeychordGeteventEnable(fd)) {
        ::close(fd);
    } else {
        KeychordRegistration.emplace(device, fd);
    }
}

void GeteventCloseDevice(const std::string& device) {
    auto it = KeychordRegistration.find(device);
    if (it == KeychordRegistration.end()) {
        LOG(ERROR) << "Device " << device << " not registered";
        return;
    }
    auto fd = (*it).second;
    unregister_epoll_handler(fd);
    KeychordRegistration.erase(it);
    ::close(fd);
}

int InotifyFd = -1;

void InotifyHandler() {
    unsigned char buf[512];

    auto res = TEMP_FAILURE_RETRY(::read(InotifyFd, buf, sizeof(buf)));
    if (res < 0) {
        PLOG(WARNING) << "could not get event";
        return;
    }

    auto EventBuf = buf;
    while (static_cast<size_t>(res) >= sizeof(buf)) {
        auto event = reinterpret_cast<inotify_event*>(EventBuf);
        if (event->len) {
            std::string devname(DevicePath);
            devname += '/';
            devname += event->name;
            if (event->mask & IN_CREATE) {
                GeteventOpenDevice(devname);
            } else {
                GeteventCloseDevice(devname);
            }
        }
        auto event_size = sizeof(inotify_event) + event->len;
        res -= event_size;
        EventBuf += event_size;
    }
}

void GeteventOpenDevice() {
    InotifyFd = ::inotify_init();
    if (InotifyFd < 0) {
        PLOG(WARNING) << "Could not instantiate inotify for " << DevicePath;
    } else if (inotify_add_watch(InotifyFd, DevicePath, IN_DELETE | IN_CREATE) < 0) {
        PLOG(WARNING) << "Could not add watch for " << DevicePath;
        ::close(InotifyFd);
        InotifyFd = -1;
    }

    std::unique_ptr<DIR, int (*)(DIR*)> device(opendir(DevicePath), closedir);
    if (!device) return;
    dirent* entry;
    while ((entry = readdir(device.get()))) {
        if (entry->d_name[0] == '.') continue;
        std::string devname(DevicePath);
        devname += '/';
        devname += entry->d_name;
        GeteventOpenDevice(devname);
    }
    if (InotifyFd >= 0) register_epoll_handler(InotifyFd, InotifyHandler);
}

void add_service_keycodes(Service* svc) {
    if (svc->keycodes().empty()) return;
    for (auto& code : svc->keycodes()) {
        if ((code < 0) || (code >= KEY_MAX)) return;
    }
    KeychordEntries.emplace_back(KeychordEntry(svc->keycodes()));
    ++keychords_count;
    svc->set_keychord_id(keychords_count);
}

}  // namespace

void keychord_init() {
    for (const auto& service : ServiceList::GetInstance()) {
        add_service_keycodes(service.get());
    }
    if (keychords_count) GeteventOpenDevice();
}

}  // namespace init
}  // namespace android

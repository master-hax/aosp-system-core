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
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <android-base/logging.h>
#include <android-base/properties.h>

#include "init.h"

// Internal types
typedef uint8_t event_id_t;  // 0 is illegal
typedef uint8_t event_type_t;
typedef uint32_t mask_t;
constexpr size_t bits_per_byte = 8;

namespace android {
namespace init {

namespace {

void handle_keychord(int id);

// libkeychord infrastructure

struct KeychordEntry {
    const std::vector<int>& keycodes;
    bool match;

    KeychordEntry(const std::vector<int>& keycodes) : keycodes(keycodes), match(false) {}
    KeychordEntry(const KeychordEntry&& copy) : keycodes(copy.keycodes), match(copy.match) {}

    bool valid() const {
        if (keycodes.empty()) return false;
        for (auto& i : keycodes) {
            if ((i < 0) || (i >= KEY_MAX)) return false;
        }
        return true;
    }
};

std::unordered_map<event_id_t, KeychordEntry> KeychordEntries;

event_id_t UniqueId() {
    unsigned id = 1;
    for (auto it = KeychordEntries.begin(); it != KeychordEntries.end();) {
        if (id == (*it).first) {
            ++id;
            if (id > static_cast<event_id_t>(-1)) return 0;
            it = KeychordEntries.begin();
        } else {
            ++it;
        }
    }
    return id;
}

bool _IsBitSet(const std::vector<mask_t>& bits, size_t bit) {
    return bits[bit / (bits_per_byte * sizeof(mask_t))] &
           (1 << (bit % (bits_per_byte * sizeof(mask_t))));
}

bool IsBitSet(const std::vector<mask_t>& bits, size_t bit) {
    if (bit >= (bits.size() * bits_per_byte * sizeof(mask_t))) return false;
    return _IsBitSet(bits, bit);
}

void SetBit(std::vector<mask_t>& bits, size_t bit, bool value = true) {
    auto idx = bit / (bits_per_byte * sizeof(mask_t));
    if (idx >= bits.size()) {
        if (!value) return;
        bits.resize(idx + 1, 0);
    }
    if (value) {
        bits[idx] |= 1 << (bit % (bits_per_byte * sizeof(mask_t)));
    } else {
        bits[idx] &= ~(1 << (bit % (bits_per_byte * sizeof(mask_t))));
    }
}

std::vector<mask_t> KeychordEntriesMask(event_type_t type) {
    std::vector<mask_t> ret;
    for (auto& e : KeychordEntries) {
        if (!e.second.valid()) continue;
        if (type == EV_SYN) {
            SetBit(ret, EV_KEY);
        } else if (type == EV_KEY) {
            for (auto& code : e.second.keycodes) {
                SetBit(ret, code);
            }
        }
    }
    return ret;
}

// getevent infrastructure

constexpr char DevicePath[] = "/dev/input";

std::unordered_map<int, bool> KeychordState;

std::vector<mask_t> KeychordCurrent;

void KeychordLambdaHandler(int fd) {
    auto it = KeychordState.find(fd);
    if (it == KeychordState.end()) return;
    auto& state = *it;
    input_event event;
    auto res = TEMP_FAILURE_RETRY(::read(state.first, &event, sizeof(event)));
    if ((res == sizeof(event)) && (event.type == EV_KEY)) {
        SetBit(KeychordCurrent, event.code, event.value);
        for (auto& e : KeychordEntries) {
            bool found = true;
            for (auto& c : e.second.keycodes) {
                if (!IsBitSet(KeychordCurrent, c)) {
                    e.second.match = false;
                    found = false;
                    break;
                }
            }
            if (!found) continue;
            if (e.second.match) continue;
            e.second.match = true;
            handle_keychord(e.first);
        }
    }
}

bool GeteventOpenDevice(std::string& device) {
    auto fd = TEMP_FAILURE_RETRY(::open(device.c_str(), O_RDWR | O_CLOEXEC));
    if (fd == -1) {
        PLOG(ERROR) << "Can not open " << device;
        return false;
    }
    // Make sure it is an event channel, should pass this ioctl call
    int version;
    if (::ioctl(fd, EVIOCGVERSION, &version)) {
        ::close(fd);
        return false;
    }
    if (!KeychordState.emplace(std::make_pair(fd, false)).second) {
        LOG(ERROR) << "Can not open " << device;
        return false;
    }
    return true;
}

void KeychordGeteventEnable() {
    static bool EviocsmaskSupported = true;
    bool EviocsmaskSucceeded = false;
    int EviocsmaskErrno = 0;
    std::unordered_set<int> something;
    for (event_type_t type = EV_SYN; type < EV_MAX; type++) {
        auto mask = KeychordEntriesMask(type);
        input_mask msg = {};
        msg.type = type;
        msg.codes_size = mask.size() * sizeof(mask_t);
        msg.codes_ptr = reinterpret_cast<uintptr_t>(mask.data());
        for (auto& state : KeychordState) {
            if (::ioctl(state.first, EVIOCSMASK, &msg) != -1) {
                EviocsmaskSucceeded = true;
            } else if (EviocsmaskSupported) {
                EviocsmaskErrno = errno;
            }
            if (mask.size() && (something.find(state.first) == something.end()) &&
                (type != EV_SYN)) {
                std::vector<mask_t> bits(mask.size(), 0);
                auto res = ::ioctl(state.first, EVIOCGBIT(type, bits.size() * sizeof(mask_t)),
                                   bits.data());
                if (res == -1) continue;
                size_t len = std::min(size_t(res), mask.size() * sizeof(mask_t)) * bits_per_byte;
                for (size_t bit = 0; bit < len; ++bit) {
                    if (_IsBitSet(bits, bit) && _IsBitSet(mask, bit)) {
                        something.emplace(state.first);
                        break;
                    }
                }
            }
        }
    }
    if (EviocsmaskSupported && !EviocsmaskSucceeded && EviocsmaskErrno) {
        errno = EviocsmaskErrno;
        PLOG(WARNING) << "EVIOCSMASK not supported";
        EviocsmaskSupported = false;
    }
    for (auto& state : KeychordState) {
        auto fd = state.first;
        auto found = something.find(fd) != something.end();
        if (found && !state.second) {
            auto fd = state.first;
            register_epoll_handler(fd, [fd]() { KeychordLambdaHandler(fd); });
            state.second = true;
        } else if (!found && state.second) {
            unregister_epoll_handler(fd);
            state.second = false;
        }
    }
}

void KeychordStatusChange() {
    static bool first;

    if (first) return;

    first = true;
    bool deviceAdded = false;
    std::unique_ptr<DIR, int (*)(DIR*)> device(opendir(DevicePath), closedir);
    if (device) {
        dirent* entry;
        while ((entry = readdir(device.get()))) {
            if (entry->d_name[0] == '.') continue;
            std::string devname(DevicePath);
            devname += '/';
            devname += entry->d_name;
            if (GeteventOpenDevice(devname)) deviceAdded = true;
        }
    }
    if (deviceAdded) return KeychordGeteventEnable();
}

int KeychordEnable(KeychordEntry&& entry) {
    if (!entry.valid()) return -1;
    auto id = UniqueId();
    if (!id) return -1;
    auto[it, emplaced] = KeychordEntries.emplace(std::make_pair(id, std::move(entry)));
    if (!emplaced) return -1;
    id = (*it).first;
    KeychordStatusChange();
    return id;
}

// init keychords handling

int keychords;

void add_service_keycodes(Service* svc) {
    auto id = KeychordEnable(KeychordEntry(svc->keycodes()));
    if (id > 0) {
        ++keychords;
        svc->set_keychord_id(id);
    }
}

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

}  // namespace

void keychord_init() {
    for (const auto& service : ServiceList::GetInstance()) {
        add_service_keycodes(service.get());
    }
}

}  // namespace init
}  // namespace android

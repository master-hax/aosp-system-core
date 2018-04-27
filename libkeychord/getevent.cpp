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

#define LOG_TAG "getevent"

// getevent interface support

#include "getevent.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <sys/cdefs.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <time.h>

#include <bitset>
#include <memory>
#include <string>
#include <vector>

#include <android-base/logging.h>

#include <keychord/keychord.h>
#include "libkeychord.h"

namespace {

// maximum of EV_MAX, KEY_MAX, REL_MAX, ABS_MAX, SW_MAX, MSC_MAX, LED_MAX,
// REP_MAX, SND_MAX is 0x2ff, fits in a uint16_t and matches internal
// representation of the array used by the keychord driver.
event_code_t KeychordCodeMaxTable[EV_MAX] = {
        // clang-format off
    [EV_SYN] = EV_MAX,
    [EV_KEY] = KEY_MAX,
    [EV_REL] = REL_MAX,
    [EV_ABS] = ABS_MAX,
    [EV_MSC] = MSC_MAX,
    [EV_SW]  = SW_MAX,
    [EV_LED] = LED_MAX,
    [EV_SND] = SND_MAX,
    [EV_REP] = REP_MAX,
    [EV_FF]  = FF_MAX,
    // [EV_PWR] = 100,
    [EV_FF_STATUS] = FF_STATUS_MAX,
    // clang-format on
};

}  // namespace

event_code_t KeychordCodeMax(event_type_t type) {
    return ((type < 0) || (type > EV_MAX)) ? 0 : KeychordCodeMaxTable[type];
}

namespace {

keychord_event_handler_fn EventHandler;

constexpr char DevicePath[] = "/dev/input";
int InotifyFd = -1;

void KeychordLambdaHandler(size_t idx);

// unique function address signature to support epoll
#define LAMBDA(idx)                                                          \
    {                                                                        \
        .fn = []() { KeychordLambdaHandler(idx); }, .version = -1, .fd = -1, \
    }
#define LAMBDA10(idx)                                                               \
    LAMBDA(idx##0), LAMBDA(idx##1), LAMBDA(idx##2), LAMBDA(idx##3), LAMBDA(idx##4), \
        LAMBDA(idx##5), LAMBDA(idx##6), LAMBDA(idx##7), LAMBDA(idx##8), LAMBDA(idx##9)

const std::vector<bool> KeychordEmptyBool;

struct KeychordState {
    void (*fn)(void);
    int version;
    int fd;
    bool registered;
    std::string name;
    std::vector<bool> available[EV_MAX];  // EV_SYN is types
} KeychordState[KEYCHORD_MAX_EPOLL_HANDLERS] = {
#if (KEYCHORD_MAX_EPOLL_HANDLERS > 9)
    LAMBDA10(),
#endif
#if (KEYCHORD_MAX_EPOLL_HANDLERS > 19)
    LAMBDA10(1),
#endif
#if (KEYCHORD_MAX_EPOLL_HANDLERS > 29)
    LAMBDA10(2),
#endif
#if (KEYCHORD_MAX_EPOLL_HANDLERS == 32)
    LAMBDA(30),  LAMBDA(31),
#endif
#if (KEYCHORD_MAX_EPOLL_HANDLERS > 39)
    LAMBDA10(3),
#endif
#if (KEYCHORD_MAX_EPOLL_HANDLERS > 49)
    LAMBDA10(4),
#endif
#if (KEYCHORD_MAX_EPOLL_HANDLERS > 59)
    LAMBDA10(5),
#endif
#if (KEYCHORD_MAX_EPOLL_HANDLERS == 64)
    LAMBDA(60),  LAMBDA(61), LAMBDA(62), LAMBDA(63),
#endif
#if (KEYCHORD_MAX_EPOLL_HANDLERS > 69)
    LAMBDA10(6),
#endif
#if (KEYCHORD_MAX_EPOLL_HANDLERS > 79)
    LAMBDA10(7),
#endif
#if (KEYCHORD_MAX_EPOLL_HANDLERS > 89)
    LAMBDA10(8),
#endif
};

class KeychordCurrent : public std::vector<bool> {
  public:
    KeychordCurrent& set(size_t bit, bool value = true) {
        if (bit >= size()) {
            if (value) {
                resize(bit + 1, false);
                std::vector<bool>::operator[](bit) = value;
            }
        } else {
            std::vector<bool>::operator[](bit) = value;
        }
        return *this;
    }

    KeychordCurrent& reset(size_t bit) {
        if (bit < size()) {
            std::vector<bool>::operator[](bit) = false;
        }
        return *this;
    }
} KeychordCurrent[EV_MAX];

constexpr size_t bits_per_byte = 8;

// bit handling for both std::vector<mask_t> and space efficient std::vector<bool>

std::vector<mask_t> bits_cast(const std::vector<bool>& bits) {
    std::vector<mask_t> ret;
    mask_t assemble = 0;
    size_t offset = 0;
    size_t zero = 0;
    bool set = false;
    for (size_t bit = 0; bit < bits.size(); ++bit) {
        if (bits[bit]) {
            set = true;
            assemble |= 1 << offset;
        }
        if (++offset == (bits_per_byte * sizeof(mask_t))) {
            if (set) {
                while (zero) {
                    ret.push_back(0);
                    --zero;
                }
                ret.push_back(assemble);
                set = false;
                assemble = 0;
            } else {
                ++zero;
            }
            offset = 0;
        }
    }
    if (offset && set) {
        while (zero) {
            ret.push_back(0);
            --zero;
        }
        ret.push_back(assemble);
    }
    return ret;
}

bool _IsBitSet(const std::vector<mask_t>& bits, size_t bit) {
    return bits[bit / (bits_per_byte * sizeof(mask_t))] &
           (1 << (bit % (bits_per_byte * sizeof(mask_t))));
}

bool IsBitSet(const std::vector<mask_t>& bits, size_t bit) {
    if (bit >= (bits.size() * bits_per_byte * sizeof(mask_t))) return false;
    return _IsBitSet(bits, bit);
}

std::vector<bool> bits_cast(const std::vector<mask_t>& bits) {
    std::vector<bool> ret;
    size_t len = bits.size() * bits_per_byte * sizeof(mask_t);
    for (size_t bit = 0; bit < len; ++bit) {
        if (_IsBitSet(bits, bit)) {
            ret.resize(bit + 1, false);
            ret[bit] = true;
        }
    }
    return ret;
}

bool _IsBitSet(const std::vector<bool>& bits, size_t bit) {
    return bits[bit];
}

bool IsBitSet(const std::vector<bool>& bits, size_t bit) {
    if (bit >= bits.size()) return false;
    return _IsBitSet(bits, bit);
}

void KeychordLambdaHandler(size_t idx) {
    if (idx >= KEYCHORD_MAX_EPOLL_HANDLERS) return;
    auto& state = KeychordState[idx];
    input_event event;
    auto res = TEMP_FAILURE_RETRY(::read(state.fd, &event, sizeof(event)));
    if (res == -1) {
        time_t now = time(nullptr);
        static time_t last;
        if ((last + 30) < now) {  // ratelimit to once every 30 seconds
            last = now;
            PLOG(WARNING) << "could not get event from " << state.name;
        }
    } else if ((res == sizeof(event)) && (event.type < EV_MAX)) {
        if (KeychordCodeMaxTable[event.type] < event.code) {
            KeychordCodeMaxTable[event.type] = event.code;
        }
        if (event.type >= state.available[EV_SYN].size()) {
            state.available[EV_SYN].resize(event.type + 1, false);
        }
        state.available[EV_SYN][event.type] = true;
        if (event.type != EV_SYN) {
            if (event.code >= state.available[event.type].size()) {  // lies?
                state.available[event.type].resize(event.code + 1, false);
            }
            state.available[event.type][event.code] = true;
            KeychordCurrent[event.type].set(event.code, event.value);
        }
        if (EventHandler != nullptr) {
            (*EventHandler)(&event, state.fd, state.name.c_str());
        }
        if (KeychordIdHandler != nullptr) {
            for (auto& e : KeychordEntries) {
                if (e.second.getType() != event.type) continue;
                LOG(VERBOSE) << "checking id=" << (int)(e.first);
                bool found = true;
                for (auto& c : e.second.getKeycodes()) {
                    LOG(VERBOSE) << "checking code=0x" << std::hex << c;
                    if (!IsBitSet(KeychordCurrent[event.type], c)) {
                        e.second.setMatch(false);
                        found = false;
                        break;
                    }
                }
                LOG(VERBOSE) << "found=" << found << " isTriggered=" << e.second.isTriggered()
                             << " isImmediate=" << e.second.isImmediate();
                if (!found) continue;
                if (e.second.isTriggered()) continue;
                if (e.second.isImmediate()) {
                    LOG(VERBOSE) << "setMatch(true,max())";
                    e.second.setMatch(true, std::chrono::milliseconds::max());
                    (*KeychordIdHandler)(e.first);
                    continue;
                }
                std::chrono::milliseconds current = std::chrono::seconds(event.time.tv_sec);
                current += std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::microseconds(event.time.tv_usec));
                LOG(VERBOSE) << "setMatch(true," << current.count() << "ms)";
                e.second.setMatch(true, current);
            }
        }
    }
}

bool GeteventOpenDevice(std::string& device) {
    ssize_t empty = -1;
    for (size_t i = 0; i < KEYCHORD_MAX_EPOLL_HANDLERS; ++i) {
        auto& state = KeychordState[i];
        if (device == state.name) {
            LOG(WARNING) << "Device " << device << " already open";
            return false;
        }
        if ((empty == -1) && (state.name.size() == 0)) {
            empty = i;
        }
    }
    if (empty == -1) {
        LOG(ERROR) << "Can not open " << device << " too many event handlers";
        return false;
    }
    auto fd = TEMP_FAILURE_RETRY(::open(device.c_str(), O_RDWR | O_CLOEXEC));
    if (fd == -1) {
        PLOG(ERROR) << "Can not open " << device;
        return false;
    }
    // Make sure it is an event channel, should pass this ioctl call
    int version;
    if (::ioctl(fd, EVIOCGVERSION, &version)) {
        PLOG(VERBOSE) << "Could not get driver version for " << device;
        ::close(fd);
        return false;
    }
#ifdef EVIOCSCLOCKID
    int clkid = CLOCK_MONOTONIC;
    if (::ioctl(fd, EVIOCSCLOCKID, &clkid)) {
        PLOG(WARNING) << "Could not set to monotonic for " << device;
    }
#endif
    auto& state = KeychordState[empty];
    state.registered = false;
    state.version = version;
    state.fd = fd;
    state.name = device;

    // Discover available and current events
    std::vector<mask_t> bits;

    // skip EV_SYN since we cannot query its available codes
    if (state.available[EV_SYN].size() <= EV_SYN) {
        state.available[EV_SYN].resize(EV_SYN + 1, false);
    }
    state.available[EV_SYN][EV_SYN] = true;
    for (event_type_t type = EV_KEY; type < EV_MAX; type++) {
        size_t len = 0;
        static constexpr size_t margin = 16 / sizeof(mask_t);
        bits.resize((KeychordCodeMax(type) + (bits_per_byte * sizeof(mask_t)) - 1) /
                            (bits_per_byte * sizeof(mask_t)) +
                        margin,
                    0);
        while (true) {
            auto res = ::ioctl(fd, EVIOCGBIT(type, bits.size() * sizeof(mask_t)), bits.data());
            if (res == -1) break;
            if (res < (bits.size() * sizeof(mask_t))) {
                len = res;
                break;
            }
            bits.resize((res + sizeof(mask_t) - 1) / sizeof(mask_t) + margin, 0);
        }
        state.available[type] = bits_cast(bits);
        if (!state.available[type].size()) continue;
        if (type >= state.available[EV_SYN].size()) {
            state.available[EV_SYN].resize(type + 1, false);
        }
        state.available[EV_SYN][type] = true;
        bits.clear();
        switch (type) {
            case EV_KEY:
                if (::ioctl(fd, EVIOCGKEY(len), bits.data()) != len) continue;
                break;
            case EV_LED:
                if (::ioctl(fd, EVIOCGLED(len), bits.data()) != len) continue;
                break;
            case EV_SND:
                if (::ioctl(fd, EVIOCGSND(len), bits.data()) != len) continue;
                break;
            case EV_SW:
                if (::ioctl(fd, EVIOCGSW(len), bits.data()) != len) continue;
                break;
            default:
                break;
        }
        for (size_t bit = 0; bit < (len * bits_per_byte); ++bit) {
            if (_IsBitSet(bits, bit)) {
                // available lied? Can not Happen
                if (bit >= state.available[type].size()) {
                    state.available[type].resize(bit + 1, false);
                }
                state.available[type][bit] = true;
                KeychordCurrent[type].set(bit);
            } else if (IsBitSet(state.available[type], bit)) {
                KeychordCurrent[type].reset(bit);
            }
        }
    }
    if ((KeychordRegisterEpollHandler != nullptr) &&
        ((EventHandler != nullptr) || (KeychordIdHandler != nullptr))) {
        if ((*KeychordRegisterEpollHandler)(state.fn, fd, device.c_str())) {
            PLOG(ERROR) << "Could not register " << device;
        } else {
            state.registered = true;
        }
    }
    return true;
}

void GeteventCloseDevice(std::string& device) {
    if (device.size() == 0) return;
    for (size_t i = 0; i < KEYCHORD_MAX_EPOLL_HANDLERS; ++i) {
        auto& state = KeychordState[i];
        if (device == state.name) {
            auto fd = state.fd;
            if (state.registered && KeychordUnregisterEpollHandler &&
                (*KeychordUnregisterEpollHandler)(fd, device.c_str())) {
                LOG(ERROR) << "Device " << device << " unregister";
            }
            state.name.erase();
            state.registered = false;
            state.version = -1;
            state.fd = -1;
            for (size_t j = 0; j < EV_MAX; ++j) {
                state.available[j].clear();
            }
            ::close(fd);
            return;
        }
    }
    LOG(ERROR) << "Device " << device << " not registered";
}

void InotifyHandler() {
    uint8_t buf[512];

    auto res = TEMP_FAILURE_RETRY(::read(InotifyFd, buf, sizeof(buf)));
    if (res == -1) {
        if (errno != EINTR) PLOG(WARNING) << "could not get event";
        return;
    }

    uint8_t* EventBuf = buf;
    bool deviceAdded = false;
    while (res >= sizeof(buf)) {
        auto event = reinterpret_cast<inotify_event*>(EventBuf);
        if (event->len) {
            std::string devname(DevicePath);
            devname += '/';
            devname += event->name;
            if (event->mask & IN_CREATE) {
                if (GeteventOpenDevice(devname)) deviceAdded = true;
            } else {
                GeteventCloseDevice(devname);
            }
        }
        auto event_size = sizeof(inotify_event) + event->len;
        res -= event_size;
        EventBuf += event_size;
    }
    if (deviceAdded && (KeychordIdHandler != nullptr)) {
        KeychordGeteventEnable();
    }
}

int KeychordStatusChange() {
    if ((EventHandler == nullptr) && (KeychordIdHandler == nullptr)) {
        if (InotifyFd != -1) {
            auto fd = InotifyFd;
            InotifyFd = -1;
            if ((KeychordUnregisterEpollHandler != nullptr) &&
                (*KeychordUnregisterEpollHandler)(fd, DevicePath)) {
                LOG(ERROR) << "Device " << DevicePath << " unregister";
            }
            ::close(fd);
        }
        for (size_t i = 0; i < KEYCHORD_MAX_EPOLL_HANDLERS; ++i) {
            GeteventCloseDevice(KeychordState[i].name);
        }
        for (event_type_t type = EV_KEY; type < EV_MAX; type++) {
            KeychordCurrent[type].clear();
        }
    } else {
        bool deviceAdded = false;
        if (InotifyFd == -1) {
            InotifyFd = inotify_init();
            bool WatchAdded = false;
            if (InotifyFd < 0) {
                PLOG(WARNING) << "Could not instantiate inotify for " << DevicePath;
            } else {
                WatchAdded = inotify_add_watch(InotifyFd, DevicePath, IN_DELETE | IN_CREATE) >= 0;
                if (!WatchAdded) {
                    PLOG(WARNING) << "Could not add watch for " << DevicePath;
                }
            }
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
            if (WatchAdded && (KeychordRegisterEpollHandler != nullptr) &&
                (*KeychordRegisterEpollHandler)(InotifyHandler, InotifyFd, DevicePath)) {
                PLOG(WARNING) << "Could not register inotify " << DevicePath;
            }
        }
        if (deviceAdded && (KeychordIdHandler != nullptr)) {
            return KeychordGeteventEnable();
        }
    }
    return 0;
}

}  // namespace

// Actually opens and starts events callback.
int keychord_register_event_handler(int d, keychord_event_handler_fn handler) {
    if (d != 0) {
        errno = EBADF;
        return -1;
    }
    if (handler == nullptr) {
        if (EventHandler == nullptr) return 0;
    } else {
        if (handler == EventHandler) return 0;
        if (EventHandler != nullptr) {
            errno = EBUSY;
            return -1;
        }
    }
    EventHandler = handler;

    if (KeychordStatusChange()) return -1;
    return d;
}

LIBKEYCHORD_HIDDEN int KeychordGeteventEnable() {
    if (KeychordIdHandler == nullptr) {
        errno = EINVAL;
        return -1;
    }
    if (KeychordEntries.empty()) return 0;

    static bool EviocsmaskSupported = true;
#ifdef EVIOCSMASK
    bool EviocsmaskSucceeded = false;
    int EviocsmaskErrno = 0;
#endif
    bool something[KEYCHORD_MAX_EPOLL_HANDLERS] = {};
    for (event_type_t type = EV_SYN; type < EV_MAX; type++) {
        auto mask = KeychordEntries.mask(type);
#ifdef EVIOCSMASK
        input_mask msg = {};
        msg.type = type;
        msg.codes_size = mask.size() * sizeof(mask_t);
        msg.codes_ptr = reinterpret_cast<uintptr_t>(mask.data());
#endif
        for (size_t i = 0; i < KEYCHORD_MAX_EPOLL_HANDLERS; ++i) {
            auto& state = KeychordState[i];
            if (state.fd < 0) continue;
            if (state.name.size() == 0) continue;
#ifdef EVIOCSMASK
            if (::ioctl(state.fd, EVIOCSMASK, &msg) != -1) {
                EviocsmaskSucceeded = true;
            } else if (EviocsmaskSupported) {
                EviocsmaskErrno = errno;
            }
#endif
            if ((something[i] == false) && (type != EV_SYN)) {
                size_t len = std::min(state.available[type].size(),
                                      mask.size() * sizeof(mask_t) * bits_per_byte);
                LOG(VERBOSE) << "KeychordState[" << i << "].available[" << type << "]["
                             << state.available[type].size() << "] mask[" << type << "]["
                             << (mask.size() * sizeof(mask_t) * bits_per_byte) << "]";
                for (size_t bit = 0; bit < len; ++bit) {
                    if (_IsBitSet(state.available[type], bit) && _IsBitSet(mask, bit)) {
                        LOG(VERBOSE) << "something: " << i << ':' << type << ":[" << bit << ']';
                        something[i] = true;
                        break;
                    }
                }
            }
        }
    }
#ifdef EVIOCSMASK
    if (EviocsmaskSupported && !EviocsmaskSucceeded && EviocsmaskErrno) {
        errno = EviocsmaskErrno;
        PLOG(WARNING) << "EVIOCSMASK not supported";
        EviocsmaskSupported = false;
    }
#else
    if (EviocsmaskSupported) {
        LOG(WARNING) << "EVIOCSMASK not supported";
        EviocsmaskSupported = false;
    }
#endif
    for (size_t i = 0; i < KEYCHORD_MAX_EPOLL_HANDLERS; ++i) {
        auto& state = KeychordState[i];
        if (state.fd < 0) continue;
        if (state.name.size() == 0) continue;
        LOG(VERBOSE) << "KeychordState[" << i << "].registered=" << state.registered
                     << " something[" << i << "]=" << something[i];
        if (!something[i] && state.registered) {
            if ((KeychordUnregisterEpollHandler != nullptr) &&
                (*KeychordUnregisterEpollHandler)(state.fd, state.name.c_str())) {
                LOG(ERROR) << "Device " << state.name << " unregister";
            }
            state.registered = false;
        } else if (something[i] && !state.registered && (KeychordIdHandler != nullptr)) {
            if (KeychordRegisterEpollHandler != nullptr) {
                if ((*KeychordRegisterEpollHandler)(state.fn, state.fd, state.name.c_str())) {
                    PLOG(ERROR) << "Could not register " << state.name;
                } else {
                    state.registered = true;
                }
            }
        }
    }
    return 0;
}

std::vector<bool> keychord_get_event_active(int d) {
    std::vector<bool> ret;
    if (d != 0) return ret;
    for (size_t i = 0; i < KEYCHORD_MAX_EPOLL_HANDLERS; ++i) {
        auto& state = KeychordState[i];
        if ((state.fd >= 0) && state.name.size() && state.registered) {
            ret.resize(i + 1, false);
            ret[i] = true;
        }
    }
    return ret;
}

bool keychord_get_event_active(int d, int idx) {
    if (d != 0) return false;
    if ((idx < 0) || (idx > KEYCHORD_MAX_EPOLL_HANDLERS)) return false;
    auto& state = KeychordState[idx];
    return (state.fd >= 0) && state.name.size() && state.registered;
}

std::vector<bool> keychord_get_event_available(int d) {
    std::vector<bool> ret;
    if (d != 0) return ret;
    for (size_t i = 0; i < KEYCHORD_MAX_EPOLL_HANDLERS; ++i) {
        auto& state = KeychordState[i];
        if ((state.fd >= 0) && state.name.size()) {
            ret.resize(i + 1, false);
            ret[i] = true;
        }
    }
    return ret;
}

bool keychord_get_event_available(int d, int idx) {
    if (d != 0) return false;
    if ((idx < 0) || (idx > KEYCHORD_MAX_EPOLL_HANDLERS)) return false;
    auto& state = KeychordState[idx];
    return (state.fd >= 0) && state.name.size();
}

int keychord_get_event_fd(int d, int idx) {
    if (d != 0) return -1;
    if ((idx < 0) || (idx > KEYCHORD_MAX_EPOLL_HANDLERS)) return -1;
    auto& state = KeychordState[idx];
    return state.fd;
}

int keychord_get_event_version(int d, int idx) {
    if (d != 0) return -1;
    if ((idx < 0) || (idx >= KEYCHORD_MAX_EPOLL_HANDLERS)) return -1;
    auto& state = KeychordState[idx];
    if ((state.fd < 0) || (state.name.size() == 0)) return -1;
    return state.version;
}

const char* keychord_get_event_name(int d, int idx) {
    if (d != 0) return nullptr;
    if ((idx < 0) || (idx >= KEYCHORD_MAX_EPOLL_HANDLERS)) return nullptr;
    auto& state = KeychordState[idx];
    if ((state.fd < 0) || (state.name.size() == 0)) return nullptr;
    return state.name.c_str();
}

std::string keychord_get_event_name_string(int d, int idx) {
    if (d != 0) return std::string("");
    if ((idx < 0) || (idx >= KEYCHORD_MAX_EPOLL_HANDLERS)) return std::string("");
    auto& state = KeychordState[idx];
    if (state.fd < 0) return std::string("");
    return state.name;
}

const std::vector<bool>& keychord_get_event_available(int d, int idx, int type) {
    if (d != 0) return KeychordEmptyBool;
    if ((idx < 0) || (idx >= KEYCHORD_MAX_EPOLL_HANDLERS)) return KeychordEmptyBool;
    if ((type < 0) || (type >= EV_MAX)) return KeychordEmptyBool;
    auto& state = KeychordState[idx];
    if ((state.fd < 0) || (state.name.size() == 0)) return KeychordEmptyBool;
    return state.available[type];
}

bool keychord_get_event_available(int d, int idx, int type, int code) {
    if (code < 0) return false;
    return IsBitSet(keychord_get_event_available(d, idx, type), code);
}

const std::vector<bool>& keychord_get_event_current(int d, int type) {
    if (d != 0) return KeychordEmptyBool;
    if ((type < 0) || (type >= EV_MAX)) return KeychordEmptyBool;
    return KeychordCurrent[type];
}

bool keychord_get_event_current(int d, int type, int code) {
    if (d != 0) return false;
    if ((type < 0) || (type >= EV_MAX)) return false;
    if (code < 0) return false;
    return IsBitSet(KeychordCurrent[type], code);
}

std::vector<bool> keychord_get_event_mask(int d, int type) {
    if (d != 0) return KeychordEmptyBool;
    if ((type < 0) || (type >= EV_MAX)) return KeychordEmptyBool;
    if (KeychordIdHandler == nullptr) return std::vector<bool>(KeychordCodeMax(type), true);
    return bits_cast(KeychordEntries.mask(type));
}

bool keychord_get_event_mask(int d, int type, int code) {
    if (d != 0) return false;
    if ((type < 0) || (type >= EV_MAX)) return false;
    if (code < 0) return false;
    if (KeychordIdHandler == nullptr) return code < KeychordCodeMax(type);
    return IsBitSet(KeychordEntries.mask(type), code);
}

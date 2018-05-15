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

#include <dirent.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <stdint.h>
#include <sys/types.h>

#include <chrono>
#include <set>
#include <string>
#include <vector>

#include <android-base/properties.h>
#include <android-base/strings.h>
#include <gtest/gtest.h>

#include "epoll.h"
#include "keychords.h"

using namespace std::chrono_literals;

namespace android {
namespace init {

namespace {

Epoll epoll;

// This class is used to inject keys.
class EventHandler {
  private:
    int fd;

  public:
    EventHandler() : fd(-1) {}
    ~EventHandler() {
        if (fd == -1) return;
        ::ioctl(fd, UI_DEV_DESTROY);
        ::close(fd);
    }

    bool init() {
        if (fd != -1) return true;
        auto _fd = TEMP_FAILURE_RETRY(::open("/dev/uinput", O_WRONLY | O_NONBLOCK | O_CLOEXEC));
        if (_fd == -1) return false;
        if (::ioctl(_fd, UI_SET_EVBIT, EV_KEY) == -1) {
            ::close(_fd);
            return false;
        }

        struct uinput_user_dev u = {
            .name = "com.google.android.init.test",
            .id.bustype = BUS_VIRTUAL,
            .id.vendor = 0x1AE0,   // Google
            .id.product = 0x494E,  // IN
            .id.version = 1,
        };
        if (TEMP_FAILURE_RETRY(::write(_fd, &u, sizeof(u))) != sizeof(u)) {
            ::close(_fd);
            return false;
        }
        // all keys
        for (uint16_t i = 0; i < KEY_MAX; ++i) {
            if (::ioctl(_fd, UI_SET_KEYBIT, i) == -1) {
                ::close(_fd);
                return false;
            }
        }
        if (::ioctl(_fd, UI_DEV_CREATE) == -1) {
            ::close(_fd);
            return false;
        }
        fd = _fd;
        return true;
    }

    bool send(struct input_event& e) {
        gettimeofday(&e.time, nullptr);
        return TEMP_FAILURE_RETRY(::write(fd, &e, sizeof(e))) == sizeof(e);
    }

    bool send(uint16_t type, uint16_t code, uint16_t value) {
        struct input_event e = {.type = type, .code = code, .value = value};
        return send(e);
    }

    bool send(uint16_t code, bool value) {
        return (code < KEY_MAX) && init() && send(EV_KEY, code, value) &&
               send(EV_SYN, SYN_REPORT, 0);
    }
};
// As a global object, remains around until process exit.
// (initializing/closing too fast can cause keys to get missed)
EventHandler ev;

std::string InitFds(const char* prefix, pid_t pid = getpid()) {
    std::string ret;

    std::string init_fds("/proc/");
    init_fds += std::to_string(pid) + "/fd";
    std::unique_ptr<DIR, decltype(&closedir)> fds(opendir(init_fds.c_str()), closedir);
    if (!fds) return ret;

    dirent* entry;
    while ((entry = readdir(fds.get()))) {
        if (entry->d_name[0] == '.') continue;
        std::string devname = init_fds + '/' + entry->d_name;
        char buf[256];
        auto retval = readlink(devname.c_str(), buf, sizeof(buf) - 1);
        if ((retval < 0) || (size_t(retval) >= (sizeof(buf) - 1))) continue;
        buf[retval] = '\0';
        if (!android::base::StartsWith(buf, prefix)) continue;
        if (ret.size() != 0) ret += ",";
        ret += buf;
    }
    return ret;
}

std::string InitInputFds() {
    return InitFds("/dev/input/");
}

std::string InitInotifyFds() {
    return InitFds("anon_inode:inotify");
}

// Must register all possible test keychords before activating
const std::set<int> escape_chord = {KEY_ESC};
const std::set<int> triple1_chord = {KEY_VOLUMEDOWN, KEY_BACKSPACE, KEY_VOLUMEUP};
const std::set<int> triple2_chord = {KEY_VOLUMEUP, KEY_BACK, KEY_VOLUMEDOWN};

std::vector<const std::set<int>*> chords = {
    &escape_chord,
    &triple1_chord,
    &triple2_chord,
};

void RelaxForMs(std::chrono::milliseconds wait = 1ms) {
    epoll.Wait(wait);
}

void SetChord(int key, bool value = true) {
    RelaxForMs();
    EXPECT_TRUE(ev.send(key, value));
}

void SetChords(const std::set<int>& chord, bool value = true) {
    for (auto& key : chord) SetChord(key, value);
    RelaxForMs();
}

void ClrChord(int key) {
    SetChord(key, false);
}

void ClrChords(const std::set<int>& chord) {
    SetChords(chord, false);
}

void instantiate() {
    static bool instantiated;
    if (instantiated) return;

    epoll.Open();
    for (auto keycodes : chords) EXPECT_TRUE(RegisterKeychord(*keycodes));
    KeychordInit(&epoll);
    for (int retry = 1000; retry; --retry) {
        RelaxForMs();
        instantiated = (InitInotifyFds().size() != 0);
        if (instantiated) break;
    }
    EXPECT_TRUE(instantiated);
}

std::set<int> last_keycodes;

}  // namespace

void HandleKeychord(const std::set<int>& keycodes) {
    last_keycodes = keycodes;
}

TEST(keychords, init_instantiated) {
    instantiate();
}

TEST(keychords, init_inotify) {
    instantiate();
    std::string before(InitInputFds());
    EXPECT_TRUE(ev.init());
    for (int retry = 1000; retry && before == InitInputFds(); --retry) RelaxForMs();
    std::string after(InitInputFds());
    EXPECT_NE(before, after);
}

TEST(keychords, key) {
    last_keycodes.clear();
    instantiate();
    EXPECT_TRUE(ev.init());
    SetChords(escape_chord);
    for (int retry = 1000; retry && escape_chord != last_keycodes; --retry) RelaxForMs();
    ClrChords(escape_chord);
    EXPECT_EQ(last_keycodes, escape_chord);
}

TEST(keychords, keys_in_series) {
    last_keycodes.clear();
    instantiate();
    EXPECT_TRUE(ev.init());
    for (auto& key : triple1_chord) {
        SetChord(key);
        ClrChord(key);
    }
    for (int retry = 1000; retry && triple1_chord != last_keycodes; --retry) RelaxForMs();
    EXPECT_NE(last_keycodes, triple1_chord);
}

TEST(keychords, keys_in_parallel) {
    last_keycodes.clear();
    instantiate();
    EXPECT_TRUE(ev.init());
    SetChords(triple2_chord);
    for (int retry = 1000; retry && triple2_chord != last_keycodes; --retry) RelaxForMs();
    ClrChords(triple2_chord);
    EXPECT_EQ(last_keycodes, triple2_chord);
}

}  // namespace init
}  // namespace android

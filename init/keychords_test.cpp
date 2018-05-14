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

#include "keychords.h"

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

using namespace std::chrono_literals;

namespace android {
namespace init {

namespace {

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

const std::set<int> escape_chord = {KEY_ESC};
const std::set<int> triple1_chord = {KEY_VOLUMEDOWN, KEY_BACKSPACE, KEY_VOLUMEUP};
const std::set<int> triple2_chord = {KEY_VOLUMEUP, KEY_BACK, KEY_VOLUMEDOWN};
const std::set<int> escape_3s_chord = {KEY_ESC, -3000};
const std::set<int> leftalt_3s_chord = {KEY_LEFTALT, -3000};

std::vector<const std::set<int>*> chords = {
    &escape_chord, &triple1_chord, &triple2_chord, &escape_3s_chord, &leftalt_3s_chord,
};

class TestFrame {
  public:
    explicit TestFrame(const std::vector<const std::set<int>*>& chords, EventHandler* ev = nullptr)
        : ev(ev) {
        epoll.Open();
        for (auto keycodes : chords) keychords.Register(*keycodes);
        keychords.Start(&epoll, [this](const std::set<int>& keycodes) {
            this->keycodes.emplace_back(keycodes);
        });
    }

    void RelaxForMs(std::chrono::milliseconds wait = 1ms) { epoll.Wait(keychords.Wait(wait)); }

    void SetChord(int key, bool value = true) {
        if (!ev) return;
        RelaxForMs();
        EXPECT_TRUE(ev->send(key, value));
    }

    void SetChords(const std::set<int>& chord, bool value = true) {
        if (!ev) return;
        for (auto& key : chord) {
            if (key >= 0) SetChord(key, value);
        }
        RelaxForMs();
    }

    void ClrChord(int key) {
        if (!ev) return;
        SetChord(key, false);
    }

    void ClrChords(const std::set<int>& chord) {
        if (!ev) return;
        SetChords(chord, false);
    }

    bool IsChord(const std::set<int>& chord) {
        for (const auto& keycode : keycodes) {
            if (keycode == chord) return true;
        }
        return false;
    }

    bool IsChord(const std::vector<const std::set<int>*>& chords) {
        for (const auto chord : chords) {
            if (IsChord(*chord)) return true;
        }
        return false;
    }

    void WaitForChord(const std::set<int>& chord) {
        for (int retry = 1000; retry && !IsChord(chord); --retry) RelaxForMs();
    }

  private:
    Epoll epoll;
    Keychords keychords;
    std::vector<const std::set<int>> keycodes;
    EventHandler* ev;
};

void duration_test(const std::set<int>& chord, std::chrono::milliseconds margin) {
    EventHandler ev;
    EXPECT_TRUE(ev.init());
    TestFrame test_frame(chords, &ev);

    auto end = android::base::boot_clock::now();
    end += std::chrono::milliseconds(-*chord.begin()) + margin;
    test_frame.SetChords(chord);
    while ((android::base::boot_clock::now() < end) && !test_frame.IsChord(chord)) {
        test_frame.RelaxForMs();
    }
    test_frame.ClrChords(chord);
    if (chord == escape_3s_chord) {
        EXPECT_TRUE(test_frame.IsChord(escape_chord));
    }
    if (margin < 0ms) {
        EXPECT_FALSE(test_frame.IsChord(chord));
    } else {
        EXPECT_GT(android::base::boot_clock::now(), end - 2 * margin);
        EXPECT_TRUE(test_frame.IsChord(chord));
    }
}

}  // namespace

TEST(keychords, init_instantiated) {
    TestFrame test_frame(chords);
    EXPECT_TRUE(InitInotifyFds().size() != 0);
}

TEST(keychords, init_inotify) {
    std::string before(InitInputFds());

    TestFrame test_frame(chords);

    EventHandler ev;
    EXPECT_TRUE(ev.init());

    for (int retry = 1000; retry && before == InitInputFds(); --retry) test_frame.RelaxForMs();
    std::string after(InitInputFds());
    EXPECT_NE(before, after);
}

TEST(keychords, key) {
    EventHandler ev;
    EXPECT_TRUE(ev.init());
    TestFrame test_frame(chords, &ev);

    test_frame.SetChords(escape_chord);
    test_frame.WaitForChord(escape_chord);
    test_frame.ClrChords(escape_chord);
    EXPECT_TRUE(test_frame.IsChord(escape_chord));
    EXPECT_FALSE(test_frame.IsChord(escape_3s_chord));
}

TEST(keychords, keys_in_series) {
    EventHandler ev;
    EXPECT_TRUE(ev.init());
    TestFrame test_frame(chords, &ev);

    for (auto& key : triple1_chord) {
        test_frame.SetChord(key);
        test_frame.ClrChord(key);
    }
    test_frame.WaitForChord(triple1_chord);
    EXPECT_FALSE(test_frame.IsChord(chords));
}

TEST(keychords, keys_in_parallel) {
    EventHandler ev;
    EXPECT_TRUE(ev.init());
    TestFrame test_frame(chords, &ev);

    test_frame.SetChords(triple2_chord);
    test_frame.WaitForChord(triple2_chord);
    test_frame.ClrChords(triple2_chord);
    EXPECT_TRUE(test_frame.IsChord(triple2_chord));
}

TEST(keychords, esc_too_short) {
    duration_test(escape_3s_chord, -250ms);
}

TEST(keychords, esc_too_long) {
    duration_test(escape_3s_chord, 250ms);
}

TEST(keychords, leftalt_too_long) {
    duration_test(leftalt_3s_chord, 250ms);
}

}  // namespace init
}  // namespace android

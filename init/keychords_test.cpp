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
#include <unistd.h>

#include <string>

#include <android-base/properties.h>
#include <android-base/strings.h>
#include <gtest/gtest.h>

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

    bool send(uint16_t code) {
        if (!send(code, true)) return false;
        usleep(1000);
        return send(code, false);
    }
};
// As a global object, remains around until process exit.
// (initializing/closing too fast can cause keys to get missed)
EventHandler ev;

std::string InitFds(const char* prefix) {
    std::string ret;

    static const char init_fd[] = "/proc/1/fd";
    std::unique_ptr<DIR, decltype(&closedir)> fds(opendir(init_fd), closedir);
    if (!fds) return ret;

    dirent* entry;
    while ((entry = readdir(fds.get()))) {
        if (entry->d_name[0] == '.') continue;
        std::string devname(init_fd);
        devname += '/';
        devname += entry->d_name;
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

bool IsBugreportTriggered() {
    return android::base::GetProperty("init.svc.bugreport", "unknown") == "running";
}

}  // namespace

TEST(keychord, init_instantiated) {
    GTEST_LOG_(INFO) << "Test assumption: "
                     << "device has at least one service marked with keycodes";
    EXPECT_TRUE((InitInputFds().size() != 0) && (InitInotifyFds().size() != 0));
}

// Test assumption: EventHandler not initialized yet (test ordering)
TEST(keychord, init_inotify) {
    EXPECT_TRUE(InitInotifyFds().size() != 0);
    std::string before(InitInputFds());
    EXPECT_TRUE(ev.init());
    for (int retry = 1000; retry && before == InitInputFds(); --retry) usleep(1000);
    std::string after(InitInputFds());
    EXPECT_NE(before, after);
}

TEST(keychord, power_or_volume_up_or_volume_down) {
    if (IsBugreportTriggered()) {
        GTEST_LOG_(INFO) << "bugreport currently being collected, bypassing test";
        return;
    }
    EXPECT_TRUE(ev.send(KEY_VOLUMEUP));
    EXPECT_TRUE(ev.send(KEY_VOLUMEDOWN));
    EXPECT_TRUE(ev.send(KEY_POWER));
    for (int retry = 1000; retry && !IsBugreportTriggered(); --retry) usleep(1000);
    EXPECT_FALSE(IsBugreportTriggered());
}

TEST(keychord, power_and_volume_up_and_volume_down) {
    if (IsBugreportTriggered()) {
        GTEST_LOG_(INFO) << "bugreport currently being collected, bypassing test";
        return;
    }
    GTEST_LOG_(INFO) << "Test assumption: "
                     << "device has a bugreport service with keycodes " << KEY_VOLUMEDOWN << " "
                     << KEY_VOLUMEUP << " " << KEY_POWER;
    EXPECT_TRUE(ev.send(KEY_VOLUMEUP, true));
    EXPECT_TRUE(ev.send(KEY_VOLUMEDOWN, true));
    EXPECT_TRUE(ev.send(KEY_POWER));
    EXPECT_TRUE(ev.send(KEY_VOLUMEDOWN, false));
    EXPECT_TRUE(ev.send(KEY_VOLUMEUP, false));
    for (int retry = 1000; retry && !IsBugreportTriggered(); --retry) usleep(1000);
    EXPECT_TRUE(IsBugreportTriggered());
}

}  // namespace init
}  // namespace android

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

#include <fcntl.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <log/log_properties.h>
#include <private/android_filesystem_config.h>

#include <gtest/gtest.h>

using namespace android::base;
using namespace std::chrono_literals;

constexpr size_t npos = std::string::npos;

namespace {

bool isWakeLock(const char* name) {
    std::string content;
    ReadFileToString("/sys/power/wake_lock", &content);
    std::vector<std::string> locks(Split(std::move(content), " \r\n\t"));
    for (auto& l : locks) {
        if (name == nullptr) {
            // nullptr matches _any_ content
            if (l.length() > 0) return true;
        } else {
            if (l == name) return true;
        }
    }
    return false;
}

bool isDisplayWakelock() {
    return isWakeLock("PowerManagerService.Display");
}

bool isWakeLock() {
    return isWakeLock("PowerManagerService.WakeLocks");
}

class eventHandler {
  private:
    int fd;

  public:
    eventHandler() : fd(-1) {}
    ~eventHandler() {
        if (fd != -1) {
            ioctl(fd, UI_DEV_DESTROY);
            close(fd);
        }
    }

    bool init() {
        if (fd != -1) {
            return true;
        }
        int _fd = TEMP_FAILURE_RETRY(open("/dev/uinput", O_WRONLY | O_NONBLOCK | O_CLOEXEC));
        if (_fd == -1) {
            return false;
        }
        if (ioctl(_fd, UI_SET_EVBIT, EV_KEY) == -1) {
            close(_fd);
            return false;
        }

        struct uinput_user_dev u = {
            .name = "com.google.android.autosuspend.test",
            .id.bustype = BUS_VIRTUAL,
            .id.vendor = 0x1AE0,   // Google
            .id.product = 0x494E,  // IN
            .id.version = 1,
        };
        if (TEMP_FAILURE_RETRY(write(_fd, &u, sizeof(u))) != sizeof(u)) {
            close(_fd);
            return false;
        }
        // all keys
        for (uint16_t i = 0; i < 256; ++i) {
            if (ioctl(_fd, UI_SET_KEYBIT, i) == -1) {
                close(_fd);
                return false;
            }
        }
        if (ioctl(_fd, UI_DEV_CREATE) == -1) {
            close(_fd);
            return false;
        }
        fd = _fd;
        return true;
    }

    bool send(struct input_event& e) {
        gettimeofday(&e.time, nullptr);
        return TEMP_FAILURE_RETRY(write(fd, &e, sizeof(e))) == sizeof(e);
    }

    // 1ms button press
    bool send(uint16_t ev) {
        if (!init()) {
            return false;
        }
        // key on
        struct input_event e = {
            // clang-format off
            .type = EV_KEY,
            .code = ev,
            .value = 1,
            // clang-format on
        };
        if (!send(e)) {
            return false;
        }
        struct input_event s = {
            // clang-format off
            .type = EV_SYN,
            .code = SYN_REPORT,
            .value = 0,
            // clang-format on
        };
        if (!send(s)) {
            return false;
        }

        usleep(1000);

        // key off
        e.value = 0;
        if (!send(e)) {
            return false;
        }
        return send(s);
    }
};
eventHandler ev;

std::string readCommand(const char* command) {
    FILE* fp = popen(command, "r");
    std::string content;
    ReadFdToString(fileno(fp), &content);
    pclose(fp);
    return content;
}

}  // namespace

TEST(suspend, auto) {
    // test requirements
    //   userdebug build
    EXPECT_TRUE(__android_log_is_debuggable());
    //   running as root
    EXPECT_EQ(getuid(), static_cast<unsigned>(AID_ROOT));
    //   wrapped by nohup & logwrap? Or in Serial console? Can not be raw adb
    close(0);
    ASSERT_TRUE(readCommand("ls -l /proc/self/fd").find(" -> /dev/pts/") == npos);

    time_t timeout = time(nullptr) + 60;
    if (isDisplayWakelock()) {
        EXPECT_TRUE(ev.send(KEY_POWER));
        while (isDisplayWakelock() && (time(nullptr) < timeout)) {
            usleep(1000);
        }
    }
    while (isWakeLock() && (time(nullptr) < timeout)) {
        usleep(1000);
    }
    EXPECT_EQ(isDisplayWakelock(), false);
    EXPECT_EQ(isWakeLock(), false);
    // any other wake locks left?
    EXPECT_EQ(isWakeLock(nullptr), false);

    std::string marker =
        StringPrintf("PM: suspend marker %lu\n", static_cast<unsigned long>(time(nullptr)));
    EXPECT_EQ(WriteStringToFile(marker, "/dev/kmsg"), true);

    // Cargo cult (insurance)
    setpgrp();
    sighandler_t hup = signal(SIGHUP, SIG_IGN);
    sighandler_t pipe = signal(SIGPIPE, SIG_IGN);

    GTEST_LOG_(INFO) << "USB will be disabled.";

    EXPECT_TRUE(SetProperty("ctl.stop", "adbd"));
    EXPECT_TRUE(WaitForProperty("init.svc.adbd", "stopped", 1s));

    // Relaxed suspend, everything should now quietly go to sleep.
    sleep(30);

    EXPECT_TRUE(SetProperty("ctl.start", "adbd"));

    // revert cargo
    signal(SIGPIPE, pipe);
    signal(SIGHUP, hup);

    std::string dmesg = readCommand("dmesg");
    size_t pos;
    ASSERT_TRUE((pos = dmesg.find(marker)) != npos);
    dmesg.erase(0, pos + marker.length());

    EXPECT_TRUE(dmesg.find("PM: suspend entry ") != npos);
    EXPECT_TRUE(dmesg.find("PM: suspend exit ") != npos);
}

TEST(suspend, force) {
    // test requirements
    //   userdebug build
    EXPECT_TRUE(__android_log_is_debuggable());
    //   running as root
    EXPECT_EQ(getuid(), static_cast<unsigned>(AID_ROOT));

    std::string marker =
        StringPrintf("PM: suspend marker %lu\n", static_cast<unsigned long>(time(nullptr)));
    EXPECT_EQ(WriteStringToFile(marker, "/dev/kmsg"), true);

    if (!WriteStringToFile("mem", "/sys/power/state")) {
        GTEST_LOG_(INFO) << "Force suspend blocked";
    }

    std::string dmesg = readCommand("dmesg");
    size_t pos;
    ASSERT_TRUE((pos = dmesg.find(marker)) != npos);
    dmesg.erase(0, pos + marker.length());

    EXPECT_TRUE(dmesg.find("PM: suspend entry ") != npos);
    EXPECT_TRUE(dmesg.find("PM: suspend exit ") != npos);

    pos = dmesg.find("PM: Device ");
    if (pos != npos) {
        std::string blockedBy = dmesg.substr(pos);
        blockedBy.erase(blockedBy.find('\n'));
        GTEST_LOG_(INFO) << blockedBy;
    }
}

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

#include <dirent.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/limits.h>
#include <linux/uinput.h>
#include <signal.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <memory>
#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <log/log_properties.h>
#include <private/android_filesystem_config.h>
#include <processgroup/processgroup.h>

#include <gtest/gtest.h>

using namespace android::base;
using namespace std::chrono_literals;

constexpr size_t npos = std::string::npos;

namespace {

std::string readCommand(const std::string& command) {
    FILE* fp = popen(command.c_str(), "r");
    std::string content;
    ReadFdToString(fileno(fp), &content);
    pclose(fp);
    return content;
}

std::string readFile(const std::string& file) {
    if (getuid() != static_cast<unsigned>(AID_ROOT)) {
        return readCommand("su root cat " + file);
    }
    std::string content;
    ReadFileToString(file, &content);
    return content;
}

bool writeFile(const std::string& file, const std::string& string) {
    if (getuid() == static_cast<unsigned>(AID_ROOT)) {
        return WriteStringToFile(string, file);
    }
    return string == readCommand("echo -n '" + string + "' | su root tee " + file + " 2>&1");
}

std::string readKmsg() {
    if (getuid() == static_cast<unsigned>(AID_ROOT)) {
        return readCommand("dmesg");
    }
    return readCommand("su root dmesg");
}

std::string readKmsg(const std::string& marker) {
    std::string content = readKmsg();
    size_t pos = content.find(marker);
    if (pos == npos) return "";
    content.erase(0, pos + marker.length());
    return content;
}

bool writeKmsg(const std::string& marker) {
    return writeFile("/dev/kmsg", marker);
}

bool stopService(const std::string& service) {
    if (getuid() == static_cast<unsigned>(AID_ROOT)) {
        SetProperty("ctl.stop", service);
    } else {
        system(("su root stop " + service).c_str());
    }
    return WaitForProperty("init.svc." + service, "stopped", 1s);
}

bool startService(const std::string& service) {
    if (getuid() == static_cast<unsigned>(AID_ROOT)) {
        SetProperty("ctl.start", service);
    } else {
        system(("su root start " + service).c_str());
    }
    return WaitForProperty("init.svc." + service, "running", 1s);
}

bool isWakeLock(const char* name) {
    std::string content = readFile("/sys/power/wake_lock");
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

// Needs privilege in order to trace up the process tree to
// recursively discover if one of the processes is adbd daemon.
bool isAdbd(pid_t pid) {
    std::string status("/proc");
    status += std::to_string(pid) + "/status";
    status = readFile(status);

    static const char nameSignature[] = "Name:";
    size_t pos = status.find(nameSignature);
    if (pos == npos) return true;
    pos += strlen(nameSignature);
    size_t epos = status.find('\n', pos);
    if (epos == npos) return true;
    if (Trim(status.substr(pos, epos - pos)) == "adbd") return true;

    static const char ppidSignature[] = "\nPPid:";
    pos = status.find(ppidSignature, epos);
    if (pos == npos) return true;
    pos += strlen(ppidSignature);
    epos = status.find('\n', pos);
    if (epos == npos) return true;
    pid = std::stoll(Trim(status.substr(pos, epos - pos)));
    if (pid <= 1) return false;

    status.clear();
    return isAdbd(pid);
}

// If we are not wrapped by a pts, then we do not need to
// elevate privilege to recursively check if parent is adbd.
bool isParentAdbd(pid_t pid) {
    static const char fds[] = "/proc/self/fd";
    std::unique_ptr<DIR, int (*)(DIR*)> d(opendir(fds), closedir);
    if (!d) return isAdbd(pid);

    dirent* de;
    while ((de = readdir(d.get()))) {
        std::string name(fds);
        name += "/";
        name += de->d_name;

        struct stat st;
        if (lstat(name.c_str(), &st)) continue;
        if (!S_ISLNK(st.st_mode)) continue;

        char buf[PATH_MAX];
        ssize_t len = readlink(name.c_str(), buf, sizeof(buf) - 1);
        if (len < 0) return isAdbd(pid);

        buf[len] = '\0';
        static const char ptsPrefix[] = "/dev/pts/";
        if (!strncmp(ptsPrefix, buf, strlen(ptsPrefix))) return isAdbd(pid);
    }
    return false;
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

}  // namespace

TEST(suspend, auto) {
    // test requirements
    //   userdebug build
    if (!__android_log_is_debuggable()) {
        GTEST_LOG_(INFO) << "Must be userdebug build, terminating test";
        return;
    }

    // Pick up system details
    //   adb running?
    bool adbd_running = GetProperty("init.svc.adbd", "") == "running";
    //   usb_hal running? What is its name?
    std::string usb_hal = Trim(readCommand(
        "getprop | sed -n 's/^[[]init[.]svc[.]\\(.*usb-hal.*\\)[]]: [[]running[]]$/\\1/p'"));
    //   current usb port_type, if confirmed set to other than "source"
    static const std::string port_file = "/sys/class/typec/port0/port_type";
    std::string port_type = readFile(port_file);
    size_t pos = port_type.find('[');
    if (pos == npos) {
        port_type = "";
    } else {
        port_type.erase(0, pos + 1);
        pos = port_type.find(']');
        port_type.erase(pos);
        port_type = Trim(port_type);
        if (port_type == "source") {
            port_type = "";
        }
    }

    // One of possibly many wake locks that developers may manually use
    // to hold off suspend.  Adding them all would be a labour of love ...
    if (isWakeLock("development")) {
        EXPECT_TRUE(writeFile("/sys/power/wake_unlock", "development"));
    }
    time_t timeout = time(nullptr) + 60;
    if (isDisplayWakelock()) {
        if (!ev.send(KEY_POWER)) {
            GTEST_LOG_(INFO) << "Failed to send KEY_POWER (ignored)";
        }
        while (isDisplayWakelock() && (time(nullptr) < timeout)) {
            usleep(1000);
        }
    }
    while (isWakeLock() && (time(nullptr) < timeout)) {
        usleep(1000);
    }
    EXPECT_FALSE(isDisplayWakelock());
    EXPECT_FALSE(isWakeLock());
    // any other wake locks left?
    EXPECT_FALSE(isWakeLock(nullptr));

    std::string marker =
        StringPrintf("PM: suspend marker %lu\n", static_cast<unsigned long>(time(nullptr)));
    EXPECT_TRUE(writeKmsg(marker));

    // Cargo cult (insurance), we do not want to be killed
    // because we need to reset test setup conditions when done.
    close(0);
    setpgrp();
    setsid();
    // prevents init from killing us if adbd (and its shell) dies
    if ((getuid() == static_cast<unsigned>(AID_ROOT))
            ? (createProcessGroup(getuid(), getpid()) < 0)
            : (!writeFile("/acct/cgroup.procs", std::to_string(getpid())))) {
        GTEST_LOG_(INFO) << "Failed to create our own cgroup (ignored)";
    }
    // prevents anyone from killing us during test
    sighandler_t handler[_NSIG];
    handler[0] = SIG_ERR;
    for (int signum = 1; signum < _NSIG; ++signum) {
        handler[signum] = signal(signum, SIG_IGN);
    }
    //   wrapped by nohup & logwrap? Or in Serial console? Can not be raw adb
    ASSERT_FALSE(isParentAdbd(getpid()));

    // Stop adbd for no other reason than cleanliness
    if (adbd_running) {
        GTEST_LOG_(INFO) << "ADBD temporarily stopped.";
        EXPECT_TRUE(stopService("adbd"));
    }

    // Stop USB HAL
    if (usb_hal.length()) {
        GTEST_LOG_(INFO) << "USB HAL temporarily stopped.";
        EXPECT_TRUE(stopService(usb_hal));
    }

    // Switch port to host (source) mode
    if (port_type.length()) {
        GTEST_LOG_(INFO) << "USB temporarily set to host mode.";
        writeFile(port_file, "source");
    }

    // Relaxed suspend, everything should now quietly go to sleep.
    sleep(30);

    // Return port to original mode
    if (port_type.length()) {
        writeFile(port_file, port_type);
    }

    // Restart USB HAL daemon
    if (usb_hal.length()) {
        EXPECT_TRUE(startService(usb_hal));
    }

    // Restart ADBD daemon
    if (adbd_running) {
        EXPECT_TRUE(startService("adbd"));
    }

    // revert cargo
    for (int signum = 1; signum < _NSIG; ++signum) {
        if (handler[signum] != SIG_ERR) signal(signum, handler[signum]);
    }

    std::string kmsg = readKmsg(marker);
    ASSERT_TRUE(kmsg != "");

    EXPECT_TRUE(kmsg.find("PM: suspend entry ") != npos);
    EXPECT_TRUE(kmsg.find("PM: suspend exit ") != npos);
}

TEST(suspend, force) {
    // test requirements
    //   userdebug build
    if (!__android_log_is_debuggable()) {
        GTEST_LOG_(INFO) << "Must be userdebug build, terminating test";
        return;
    }

    std::string marker =
        StringPrintf("PM: suspend marker %lu\n", static_cast<unsigned long>(time(nullptr)));
    EXPECT_TRUE(writeKmsg(marker));

    // ToDo: use libsuspend API for force suspend w/o loss of wake sources.
    // ToDo: similar test requiring the user to manually hit the power button.
    // Should not disable wake sources, count on _something_ to re-wake us
    // to continue.
    if (!writeFile("/sys/power/state", "mem")) {
        GTEST_LOG_(INFO) << "Force suspend blocked (ignored)";
    }

    std::string kmsg = readKmsg(marker);
    ASSERT_TRUE(kmsg != "");

    EXPECT_TRUE(kmsg.find("PM: suspend entry ") != npos);
    EXPECT_TRUE(kmsg.find("PM: suspend exit ") != npos);

    size_t pos = kmsg.find("PM: Device ");
    if (pos != npos) {
        std::string blockedBy = kmsg.substr(pos);
        blockedBy.erase(blockedBy.find('\n'));
        GTEST_LOG_(INFO) << blockedBy;
    }
}

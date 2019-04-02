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

#include "first_stage_init.h"

#include <dirent.h>
#include <fcntl.h>
#include <linux/module.h>
#include <paths.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/android_reboot.h>
#include <private/android_filesystem_config.h>

#include "first_stage_mount.h"
#include "reboot_utils.h"
#include "switch_root.h"
#include "util.h"

using android::base::boot_clock;

using namespace std::literals;

namespace android {
namespace init {

namespace {

void FreeRamdisk(DIR* dir, dev_t dev) {
    int dfd = dirfd(dir);

    dirent* de;
    while ((de = readdir(dir)) != nullptr) {
        if (de->d_name == "."s || de->d_name == ".."s) {
            continue;
        }

        bool is_dir = false;

        if (de->d_type == DT_DIR || de->d_type == DT_UNKNOWN) {
            struct stat info;
            if (fstatat(dfd, de->d_name, &info, AT_SYMLINK_NOFOLLOW) != 0) {
                continue;
            }

            if (info.st_dev != dev) {
                continue;
            }

            if (S_ISDIR(info.st_mode)) {
                is_dir = true;
                auto fd = openat(dfd, de->d_name, O_RDONLY | O_DIRECTORY);
                if (fd >= 0) {
                    auto subdir =
                            std::unique_ptr<DIR, decltype(&closedir)>{fdopendir(fd), closedir};
                    if (subdir) {
                        FreeRamdisk(subdir.get(), dev);
                    } else {
                        close(fd);
                    }
                }
            }
        }
        unlinkat(dfd, de->d_name, is_dir ? AT_REMOVEDIR : 0);
    }
}

bool ForceNormalBoot() {
    std::string cmdline;
    android::base::ReadFileToString("/proc/cmdline", &cmdline);
    return cmdline.find("androidboot.force_normal_boot=1") != std::string::npos;
}

void ParseRamdiskInitRc() {
    std::string initrc;
    if (!android::base::ReadFileToString("/init.rc", &initrc)) return;
    auto lines = android::base::Split(initrc, "\r\n");
    initrc.clear();

    LOG(INFO) << "Parsing file /init.rc...";

    // Parse out the on first-stage-init section(s) only.
    auto in_first_stage_init_section = false;
    for (auto& line : lines) {
        // strip out comments, replace tabs with spaces
        auto pos = line.find('#');
        if (pos != std::string::npos) line.erase(pos);
        std::replace(line.begin(), line.end(), '\t', ' ');
        if (line == "on first-stage-init") {
            in_first_stage_init_section = true;
            continue;
        }
        if (!in_first_stage_init_section) continue;
        // Only lines allowed:
        //
        // ^on first-stage-init
        // ^\n (skip)
        // ^ insmod [-f] filename args...
        //
        // everything else terminates parse for this group
        if (line.empty()) continue;
        if (line[0] != ' ') {
            if (!android::base::StartsWith(line, "on ")) {
                LOG(ERROR) << "Syntax error " << line;
            }
            in_first_stage_init_section = false;
            continue;
        }
        line = android::base::Trim(line);
        if (line.empty()) continue;

        auto args = android::base::Split(line, " ");

        // KISS We only support one command
        auto it = args.begin();
        if (*it != "insmod") {
            LOG(ERROR) << "Unsupported command " << line;
            in_first_stage_init_section = false;
            continue;
        }
        if (++it == args.end()) {
            LOG(ERROR) << "Too few arguments " << line;
            in_first_stage_init_section = false;
            continue;
        }
        int flags = 0;
        if (*it == "-f") {
            flags = MODULE_INIT_IGNORE_VERMAGIC | MODULE_INIT_IGNORE_MODVERSIONS;
            if (++it == args.end()) {
                LOG(ERROR) << "No filename argument " << line;
                in_first_stage_init_section = false;
                continue;
            }
        }

        auto filename = *it++;
        auto options = android::base::Join(std::vector<std::string>(it, args.end()), ' ');

        LOG(INFO) << "insmod " << filename << " " << options;

        android::base::unique_fd fd(
                TEMP_FAILURE_RETRY(open(filename.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
        if (fd == -1) {
            PLOG(ERROR) << "open(\"" << filename << "\") failed";
            continue;
        }

        auto rc = syscall(__NR_finit_module, fd.get(), options.c_str(), flags);
        if (rc == -1) {
            PLOG(ERROR) << "finit_module for \"" << filename << "\" failed";
        }
    }
}

}  // namespace

int FirstStageMain(int argc, char** argv) {
    if (REBOOT_BOOTLOADER_ON_PANIC) {
        InstallRebootSignalHandlers();
    }

    boot_clock::time_point start_time = boot_clock::now();

    std::vector<std::pair<std::string, int>> errors;
#define CHECKCALL(x) \
    if (x != 0) errors.emplace_back(#x " failed", errno);

    // Clear the umask.
    umask(0);

    CHECKCALL(clearenv());
    CHECKCALL(setenv("PATH", _PATH_DEFPATH, 1));
    // Get the basic filesystem setup we need put together in the initramdisk
    // on / and then we'll let the rc file figure out the rest.
    CHECKCALL(mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755"));
    CHECKCALL(mkdir("/dev/pts", 0755));
    CHECKCALL(mkdir("/dev/socket", 0755));
    CHECKCALL(mount("devpts", "/dev/pts", "devpts", 0, NULL));
#define MAKE_STR(x) __STRING(x)
    CHECKCALL(mount("proc", "/proc", "proc", 0, "hidepid=2,gid=" MAKE_STR(AID_READPROC)));
#undef MAKE_STR
    // Don't expose the raw commandline to unprivileged processes.
    CHECKCALL(chmod("/proc/cmdline", 0440));
    gid_t groups[] = {AID_READPROC};
    CHECKCALL(setgroups(arraysize(groups), groups));
    CHECKCALL(mount("sysfs", "/sys", "sysfs", 0, NULL));
    CHECKCALL(mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", 0, NULL));

    CHECKCALL(mknod("/dev/kmsg", S_IFCHR | 0600, makedev(1, 11)));

    if constexpr (WORLD_WRITABLE_KMSG) {
        CHECKCALL(mknod("/dev/kmsg_debug", S_IFCHR | 0622, makedev(1, 11)));
    }

    CHECKCALL(mknod("/dev/random", S_IFCHR | 0666, makedev(1, 8)));
    CHECKCALL(mknod("/dev/urandom", S_IFCHR | 0666, makedev(1, 9)));

    // This is needed for log wrapper, which gets called before ueventd runs.
    CHECKCALL(mknod("/dev/ptmx", S_IFCHR | 0666, makedev(5, 2)));
    CHECKCALL(mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3)));

    // These below mounts are done in first stage init so that first stage mount can mount
    // subdirectories of /mnt/{vendor,product}/.  Other mounts, not required by first stage mount,
    // should be done in rc files.
    // Mount staging areas for devices managed by vold
    // See storage config details at http://source.android.com/devices/storage/
    CHECKCALL(mount("tmpfs", "/mnt", "tmpfs", MS_NOEXEC | MS_NOSUID | MS_NODEV,
                    "mode=0755,uid=0,gid=1000"));
    // /mnt/vendor is used to mount vendor-specific partitions that can not be
    // part of the vendor partition, e.g. because they are mounted read-write.
    CHECKCALL(mkdir("/mnt/vendor", 0755));
    // /mnt/product is used to mount product-specific partitions that can not be
    // part of the product partition, e.g. because they are mounted read-write.
    CHECKCALL(mkdir("/mnt/product", 0755));

    // /apex is used to mount APEXes
    CHECKCALL(mount("tmpfs", "/apex", "tmpfs", MS_NOEXEC | MS_NOSUID | MS_NODEV,
                    "mode=0755,uid=0,gid=0"));

#undef CHECKCALL

    // Now that tmpfs is mounted on /dev and we have /dev/kmsg, we can actually
    // talk to the outside world...
    // We need to set up stdin/stdout/stderr for child processes forked from first
    // stage init as part of the mount process.  This closes /dev/console if the
    // kernel had previously opened it.
    auto reboot_bootloader = [](const char*) { RebootSystem(ANDROID_RB_RESTART2, "bootloader"); };
    InitKernelLogging(argv, reboot_bootloader);

    if (!errors.empty()) {
        for (const auto& [error_string, error_errno] : errors) {
            LOG(ERROR) << error_string << " " << strerror(error_errno);
        }
        LOG(FATAL) << "Init encountered errors starting first stage, aborting";
    }

    LOG(INFO) << "init first stage started!";

    auto old_root_dir = std::unique_ptr<DIR, decltype(&closedir)>{opendir("/"), closedir};
    if (!old_root_dir) {
        PLOG(ERROR) << "Could not opendir(\"/\"), not freeing ramdisk";
    }

    struct stat old_root_info;
    if (stat("/", &old_root_info) != 0) {
        PLOG(ERROR) << "Could not stat(\"/\"), not freeing ramdisk";
        old_root_dir.reset();
    }

    if (ForceNormalBoot()) {
        mkdir("/first_stage_ramdisk", 0755);
        // SwitchRoot() must be called with a mount point as the target, so we bind mount the
        // target directory to itself here.
        if (mount("/first_stage_ramdisk", "/first_stage_ramdisk", nullptr, MS_BIND, nullptr) != 0) {
            LOG(FATAL) << "Could not bind mount /first_stage_ramdisk to itself";
        }
        SwitchRoot("/first_stage_ramdisk");
    }

    ParseRamdiskInitRc();

    // If this file is present, the second-stage init will use a userdebug sepolicy
    // and load adb_debug.prop to allow adb root, if the device is unlocked.
    if (access("/force_debuggable", F_OK) == 0) {
        setenv("INIT_FORCE_DEBUGGABLE", "true", 1);
    }

    if (!DoFirstStageMount()) {
        LOG(FATAL) << "Failed to mount required partitions early ...";
    }

    struct stat new_root_info;
    if (stat("/", &new_root_info) != 0) {
        PLOG(ERROR) << "Could not stat(\"/\"), not freeing ramdisk";
        old_root_dir.reset();
    }

    if (old_root_dir && old_root_info.st_dev != new_root_info.st_dev) {
        FreeRamdisk(old_root_dir.get(), old_root_info.st_dev);
    }

    SetInitAvbVersionInRecovery();

    static constexpr uint32_t kNanosecondsPerMillisecond = 1e6;
    uint64_t start_ms = start_time.time_since_epoch().count() / kNanosecondsPerMillisecond;
    setenv("INIT_STARTED_AT", std::to_string(start_ms).c_str(), 1);

    const char* path = "/system/bin/init";
    const char* args[] = {path, "selinux_setup", nullptr};
    execv(path, const_cast<char**>(args));

    // execv() only returns if an error happened, in which case we
    // panic and never fall through this conditional.
    PLOG(FATAL) << "execv(\"" << path << "\") failed";

    return 1;
}

}  // namespace init
}  // namespace android

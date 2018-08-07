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
#include <mntent.h>
#include <paths.h>
#include <seccomp_policy.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <cutils/android_reboot.h>
#include <private/android_filesystem_config.h>
#include <selinux/android.h>

#include "first_stage_mount.h"
#include "reboot_utils.h"
#include "selinux.h"
#include "util.h"

using android::base::boot_clock;
using android::base::StartsWith;

using namespace std::literals;

namespace android {
namespace init {

static void GlobalSeccomp() {
    import_kernel_cmdline(false, [](const std::string& key, const std::string& value,
                                    bool in_qemu) {
        if (key == "androidboot.seccomp" && value == "global" && !set_global_seccomp_filter()) {
            LOG(FATAL) << "Failed to globally enable seccomp!";
        }
    });
}

static void FreeRamdisk(DIR* dir, dev_t dev) {
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

static std::vector<std::string> GetMounts(const std::string& new_root) {
    auto fp = std::unique_ptr<std::FILE, decltype(&endmntent)>{setmntent("/proc/mounts", "re"),
                                                               endmntent};
    if (fp == nullptr) {
        PLOG(FATAL) << "Failed to open /proc/mounts";
    }

    std::vector<std::string> result;
    mntent* mentry;
    while ((mentry = getmntent(fp.get())) != nullptr) {
        // We won't try to move rootfs.
        if (mentry->mnt_dir == "/"s) {
            continue;
        }

        // The new root mount is handled separately.
        if (mentry->mnt_dir == new_root) {
            continue;
        }

        // Move operates on subtrees, so do not try to move children of other mounts.
        if (std::find_if(result.begin(), result.end(), [&mentry](const auto& older_mount) {
                return StartsWith(mentry->mnt_dir, older_mount);
            }) != result.end()) {
            continue;
        }

        result.emplace_back(mentry->mnt_dir);
    }

    return result;
}

static void SwitchRoot(const std::string& new_root) {
    auto mounts = GetMounts(new_root);

    for (const auto& mount_path : mounts) {
        auto new_mount_path = new_root + mount_path;
        if (mount(mount_path.c_str(), new_mount_path.c_str(), nullptr, MS_MOVE, nullptr) != 0) {
            PLOG(FATAL) << "Unable to move mount at '" << mount_path << "'";
        }
    }

    auto old_root_dir = std::unique_ptr<DIR, decltype(&closedir)>{opendir("/"), closedir};
    if (!old_root_dir) {
        PLOG(ERROR) << "Could not opendir(\"/\"), not freeing ramdisk";
    }

    struct stat old_root_info;
    if (stat("/", &old_root_info) != 0) {
        PLOG(ERROR) << "Could not stat(\"/\"), not freeing ramdisk";
        old_root_dir.reset();
    }

    if (chdir(new_root.c_str()) != 0) {
        PLOG(FATAL) << "Could not chdir to new_root, '" << new_root << "'";
    }

    if (mount(new_root.c_str(), "/", nullptr, MS_MOVE, nullptr) != 0) {
        PLOG(FATAL) << "Unable to move root mount to new_root, '" << new_root << "'";
    }

    if (chroot(".") != 0) {
        PLOG(FATAL) << "Unable to chroot to new root";
    }

    if (old_root_dir) {
        FreeRamdisk(old_root_dir.get(), old_root_info.st_dev);
    }
}

int main(int argc, char** argv) {
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

#undef CHECKCALL

    // Now that tmpfs is mounted on /dev and we have /dev/kmsg, we can actually
    // talk to the outside world...
    android::base::InitLogging(argv, &android::base::KernelLogger, [](const char*) {
        RebootSystem(ANDROID_RB_RESTART2, "bootloader");
    });

    if (!errors.empty()) {
        for (const auto& [error_string, error_errno] : errors) {
            LOG(ERROR) << error_string << " " << strerror(error_errno);
        }
        LOG(FATAL) << "Init encountered errors starting first stage, aborting";
    }

    LOG(INFO) << "init first stage started!";

    if (!DoFirstStageMount()) {
        LOG(FATAL) << "Failed to mount required partitions early ...";
    }

    SetInitAvbVersionInRecovery();

    // Does this need to be done in first stage init or can it be done later?
    // Enable seccomp if global boot option was passed (otherwise it is enabled in zygote).
    GlobalSeccomp();

    // If we're not system-as-root, we need to switch root from our initramfs to /system.
    if (access("/system/bin/init", F_OK) != 0) {
        SwitchRoot("/system");
    }

    // Set up SELinux, loading the SELinux policy.
    SelinuxSetupKernelLogging();
    SelinuxInitialize();

    static constexpr uint32_t kNanosecondsPerMillisecond = 1e6;
    uint64_t start_ms = start_time.time_since_epoch().count() / kNanosecondsPerMillisecond;
    setenv("INIT_STARTED_AT", std::to_string(start_ms).c_str(), 1);

    const char* path = "/system/bin/init";
    const char* args[] = {path, nullptr};
    execv(path, const_cast<char**>(args));

    // execv() only returns if an error happened, in which case we
    // panic and never fall through this conditional.
    PLOG(FATAL) << "execv(\"" << path << "\") failed";

    return 1;
}

}  // namespace init
}  // namespace android

int main(int argc, char** argv) {
    return android::init::main(argc, argv);
}

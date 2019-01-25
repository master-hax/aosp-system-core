/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <errno.h>
#include <getopt.h>
#include <libavb_user/libavb_user.h>
#include <sys/cdefs.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <bootloader_message/bootloader_message.h>
#include <cutils/android_reboot.h>
#include <fs_mgr_overlayfs.h>
#include <fs_mgr_priv.h>
#include <fstab/fstab.h>

namespace {

[[noreturn]] void usage(int exit_status) {
    LOG(INFO) << getprogname()
              << " [-h] [-T fstab_file] [-a] [partition]...\n"
                 "-a\t\tremount all (default if no partitions specified)\n"
                 "-h\t\tthis help\n"
                 "-R\t\treboot if necessary to facilitate remount\n"
                 "-T\t\tcustom fstab file location\n"
                 "partition\texisting partition\n"
                 "\n"
                 "Remount the specified partitions read-write.\n"
                 "Assumes verity has been disabled on the partion(s)";

    exit(exit_status);
}

bool remountable_partition(const FstabEntry& entry) {
    if (entry.fs_mgr_flags.vold_managed) return false;
    if (entry.fs_mgr_flags.recovery_only) return false;
    if (entry.fs_mgr_flags.slot_select_other) return false;
    if (!(entry.flags & MS_RDONLY)) return false;
    return true;
}

[[noreturn]] void reboot(bool dedupe) {
    if (dedupe) {
        LOG(INFO) << "Rebooting to dedupe filesystem";
    } else {
        LOG(INFO) << "Rebooting after disabling verity";
    }
    ::sync();
    android::base::SetProperty(ANDROID_RB_PROPERTY, dedupe ? "reboot,recovery" : "reboot,remount");
    sleep(60);
    exit(0);  // SUCCESS
}

}  // namespace

__BEGIN_DECLS

int main(int argc, char* argv[]);

__END_DECLS

int main(int argc, char* argv[]) {
    android::base::InitLogging(argv, &android::base::StderrLogger);

    enum {
        SUCCESS,
        NOT_USERDEBUG,
        BADARG,
        NOT_ROOT,
        NO_FSTAB,
        INVALID_PARTITION,
        VERITY_PARTITION,
        BAD_OVERLAY,
        NO_MOUNTS,
        REMOUNT_FAILED,
    } retval = SUCCESS;

    // If somehow this executable is delivered on a "user" build, it can
    // not function, so providing a clear message to the caller rather than
    // letting if fall through and provide a lot of confusing failure messages.
    if (!ALLOW_ADBD_DISABLE_VERITY || (android::base::GetProperty("ro.debuggable", "0") != "1")) {
        LOG(ERROR) << "only functions on userdebug or eng builds";
        retval = NOT_USERDEBUG;
        exit(retval);
    }

    const char* fstab_file = nullptr;
    auto all = false;
    auto can_reboot = false;

    struct option longopts[] = {
            {"all", no_argument, nullptr, 'a'},
            {"help", no_argument, nullptr, 'h'},
            {"reboot", no_argument, nullptr, 'R'},
            {"fstab", required_argument, nullptr, 'T'},
            {0, 0, nullptr, 0},
    };
    for (int opt; (opt = getopt_long(argc, argv, "ahRT:", longopts, nullptr)) != -1;) {
        switch (opt) {
            case 'a':
                all = true;
                break;
            case 'R':
                can_reboot = true;
                break;
            case 'T':
                fstab_file = optarg;
                break;
            default:
                LOG(ERROR) << "Bad Argument -" << char(opt);
                retval = BADARG;
                // FALLTHRU (for gcc, lint, pcc, etc; and following for clang)
                FALLTHROUGH_INTENDED;
            case 'h':
                usage(retval);
                break;
        }
    }

    // Make sure we are root.
    if (getuid() != 0) {
        LOG(ERROR) << "must be run as root";
        retval = NOT_ROOT;
        exit(retval);
    }

    // Read the fstab.
    Fstab fstab;
    auto fstab_read = false;
    if (fstab_file) {
        fstab_read = ReadFstabFromFile(fstab_file, &fstab);
    } else {
        fstab_read = ReadDefaultFstab(&fstab);
    }
    if (!fstab_read || fstab.empty()) {
        PLOG(ERROR) << "Failed to read fstab";
        retval = NO_FSTAB;
        exit(retval);
    }

    // Parse the valid partition arguments.
    std::vector<FstabEntry> partitions;
    for (; argc > optind; ++optind) {
        std::string partition(argv[optind]);
        auto const it = std::find_if(fstab.begin(), fstab.end(), [partition](const auto& entry) {
            if (!remountable_partition(entry)) return false;
            if ((partition == "system") && (entry.mount_point == "/")) return true;
            if (partition == entry.mount_point) return true;
            if (partition == android::base::Basename(entry.mount_point)) return true;
            return false;
        });
        if (it == fstab.end()) {
            LOG(ERROR) << "Invalid partition " << partition << ", skipping";
            retval = INVALID_PARTITION;
            continue;
        }
        auto mount_point = it->mount_point;
        if (std::find_if(partitions.begin(), partitions.end(), [mount_point](const auto& previous) {
                return mount_point == previous.mount_point;
            }) == partitions.end()) {
            partitions.emplace_back(*it);
        }
    }

    // Deal with all partitions case.
    if ((all || partitions.empty()) && !retval) {
        for (auto const& entry : fstab) {
            if (remountable_partition(entry) &&
                (std::find_if(partitions.begin(), partitions.end(), [entry](const auto& previous) {
                     return android::base::StartsWith(entry.mount_point, previous.mount_point);
                 }) == partitions.end())) {
                partitions.emplace_back(entry);
            }
        }
    }

    // Check verity and optionally setup overlayfs backing.
    auto reboot_later = false;
    for (auto [verity, it] =
                 std::make_pair(fs_mgr_overlayfs_verity_enabled_list(), partitions.begin());
         it != partitions.end();) {
        auto& entry = *it;
        auto partition = android::base::Basename(entry.mount_point);
        if (entry.mount_point == "/") partition = "system";
        if (std::find(verity.begin(), verity.end(), partition) != verity.end()) {
            LOG(WARNING) << "Verity enabled on " << entry.mount_point;
            if (can_reboot &&
                (android::base::GetProperty("ro.boot.vbmeta.devices_state", "") != "locked")) {
                AvbOps* ops = avb_ops_user_new();
                if (ops != nullptr) {
                    auto ret = avb_user_verity_set(
                            ops, android::base::GetProperty("ro.boot.slot_suffix", "").c_str(),
                            false);
                    avb_ops_user_free(ops);
                    if (ret) {
                        if (fs_mgr_overlayfs_valid() == OverlayfsValidResult::kNotSupported) {
                            retval = VERITY_PARTITION;
                            // w/o overlayfs available, also check for dedupe
                            reboot_later = true;
                            ++it;
                            continue;
                        }
                        reboot(false);
                    }
                }
            }
            LOG(ERROR) << "Skipping " << entry.mount_point;
            retval = VERITY_PARTITION;
            it = partitions.erase(it);
            continue;
        }

        auto change = false;
        errno = 0;
        if (fs_mgr_overlayfs_setup(nullptr, entry.mount_point.c_str(), &change)) {
            if (change) {
                LOG(INFO) << "Using overlayfs for " << entry.mount_point;
            }
        } else if (errno) {
            PLOG(ERROR) << "Overlayfs setup for " << entry.mount_point << " failed, skipping";
            retval = BAD_OVERLAY;
            it = partitions.erase(it);
            continue;
        }
        ++it;
    }

    if (partitions.empty()) {
        LOG(WARNING) << "No partitions to remount";
        return retval;
    }

    // Mount overlayfs.
    fs_mgr_overlayfs_mount_all(&partitions);

    // Get actual mounts.
    Fstab mounts;
    if (!ReadFstabFromFile("/proc/mounts", &mounts) || mounts.empty()) {
        PLOG(ERROR) << "Failed to read /proc/mounts";
        retval = NO_MOUNTS;
    }

    // Remount selected partitions.
    for (auto& entry : partitions) {
        // unlock the r/o key for the mount point device
        if (entry.fs_mgr_flags.logical) {
            fs_mgr_update_logical_partition(&entry);
        }
        auto blk_device = entry.blk_device;
        auto mount_point = entry.mount_point;

        if (!mounts.empty()) {
            auto it = mounts.end();
            do {
                --it;
                if (mount_point == it->mount_point) {
                    blk_device = it->blk_device;
                    break;
                }
                if ((mount_point == "/") && (it->mount_point == "/system")) {
                    if (blk_device != "/dev/root") blk_device = it->blk_device;
                    mount_point = "/system";
                    break;
                }
            } while (it != mounts.begin());
        }
        fs_mgr_set_blk_ro(blk_device, false);

        // Now remount!
        if (mount(blk_device.c_str(), mount_point.c_str(), entry.fs_type.c_str(), MS_REMOUNT,
                  nullptr) == 0) {
            continue;
        }
        if ((errno == EINVAL) && (mount_point != entry.mount_point)) {
            mount_point = entry.mount_point;
            if (mount(blk_device.c_str(), mount_point.c_str(), entry.fs_type.c_str(), MS_REMOUNT,
                      nullptr) == 0) {
                continue;
            }
        }
        PLOG(WARNING) << "failed to remount partition dev:" << blk_device << " mnt:" << mount_point;
        // If errno = EROFS at this point, we are dealing with r/o
        // filesystem types like squashfs, erofs or ext4 dedupe. We will
        // consider such a device that does not have CONFIG_OVERLAY_FS
        // in the kernel as a misconfigured; except for ext4 dedupe.
        if ((errno == EROFS) && can_reboot) {
            const std::vector<std::string> msg = {"--fsck_unshare_blocks"};
            std::string err;
            if (write_bootloader_message(msg, &err)) reboot(true);
            LOG(ERROR) << "Failed to set bootloader message: " << err;
            errno = EROFS;
        }
        retval = REMOUNT_FAILED;
    }

    if (reboot_later) reboot(false);

    return retval;
}

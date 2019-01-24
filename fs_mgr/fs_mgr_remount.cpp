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
#include <sys/cdefs.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <fs_mgr_overlayfs.h>
#include <fs_mgr_priv.h>
#include <fstab/fstab.h>

using namespace std::literals;

namespace {

[[noreturn]] void usage(int exit_status) {
    LOG(INFO) << getprogname()
              << " [-h] [-T fstab_file] [-a] [partition]...\n"
                 "-a\t\tremount all (default if no partitions specified)\n"
                 "-h\t\tthis help\n"
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

    // Paranoia Insurance (remount is not delivered to "user" builds
    if (!ALLOW_ADBD_DISABLE_VERITY) {
        LOG(ERROR) << "only functions on userdebug or eng builds";
        retval = NOT_USERDEBUG;
        exit(retval);
    }

    const char* fstab_file = nullptr;
    auto all = false;

    struct option longopts[] = {
            {"all", no_argument, nullptr, 'a'},
            {"help", no_argument, nullptr, 'h'},
            {"fstab", required_argument, nullptr, 'T'},
            {0, 0, nullptr, 0},
    };
    for (int opt; (opt = getopt_long(argc, argv, "ahT:", longopts, nullptr)) != -1;) {
        switch (opt) {
            case 'a':
                all = true;
                break;
            case 'T':
                fstab_file = optarg;
                break;
            default:
                LOG(ERROR) << "Bad Argument -" << opt;
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

    // Read the default fstab.
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
    for (auto [verity, it] =
                 std::make_pair(fs_mgr_overlayfs_verity_enabled_list(), partitions.begin());
         it != partitions.end();) {
        auto& entry = *it;
        auto partition = android::base::Basename(entry.mount_point);
        if (entry.mount_point == "/") partition = "system";
        if (std::find(verity.begin(), verity.end(), partition) != verity.end()) {
            LOG(ERROR) << "Verity enabled on " << entry.mount_point << ", skipping";
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
            PLOG(ERROR) << "Overlayfs setup for " << entry.mount_point << " failed";
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
                  nullptr) < 0) {
            PLOG(ERROR) << "failed to remount partition dev:" << blk_device
                        << " mnt:" << mount_point;
            retval = REMOUNT_FAILED;
        }
    }

    return retval;
}

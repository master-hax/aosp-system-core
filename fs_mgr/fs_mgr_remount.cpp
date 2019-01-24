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
#include <vector>

#include <android-base/file.h>
#include <android-base/strings.h>
#include <fs_mgr_overlayfs.h>
#include <fstab/fstab.h>

using namespace std::literals;

namespace {

[[noreturn]] void usage(int exit_status) {
    fprintf(stderr,
            "%s [-h] [-T fstab_file] [partition]...\n"
            "-h\t\tthis help\n"
            "-T\t\tcustom fstab file location\n"
            "partition\texisting partition\n"
            "\n"
            "Remount the specified partitions read-write.\n"
            "Assumes verity has been disabled on the partion(s)\n",
            getprogname());

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
    enum {
        SUCCESS,
        NOT_USERDEBUG,
        BADARG,
        NOT_ROOT,
        NO_FSTAB,
        UNKNOWN_PARTITION,
        REMOUNT_FAILED,
    } retval = SUCCESS;

    if (!ALLOW_ADBD_DISABLE_VERITY) {
        fprintf(stderr, "only functions on userdebug or eng builds\n");
        retval = NOT_USERDEBUG;
        exit(retval);
    }

    const char* fstab_file = nullptr;

    struct option longopts[] = {
            {"help", no_argument, nullptr, 'h'},
            {"fstab", no_argument, nullptr, 'T'},
            {0, 0, nullptr, 0},
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "hT:", longopts, nullptr)) != -1) {
        switch (opt) {
            case 'h':
                usage(retval);
                break;
            case 'T':
                fstab_file = optarg;
                break;
            default:
                retval = BADARG;
                usage(retval);
                break;
        }
    }

    // Make sure we are root.
    if (getuid() != 0) {
        fprintf(stderr, "must be run as root\n");
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
        fprintf(stderr, "Failed to read fstab\n");
        retval = NO_FSTAB;
        exit(retval);
    }

    // Parse the valid partition arguments.
    std::vector<FstabEntry> partitions;
    while (argc > optind) {
        std::string partition(argv[optind]);
        if ((partition == "all") && (argc == (optind + 1))) {
            partitions.clear();
            retval = SUCCESS;
            break;
        }
        auto const it = std::find_if(fstab.begin(), fstab.end(), [partition](const auto& entry) {
            if (!remountable_partition(entry)) return false;
            if ((partition == "system") && (entry.mount_point == "/")) return true;
            if (partition == entry.mount_point) return true;
            if (partition == android::base::Basename(entry.mount_point)) return true;
            return false;
        });
        if (it == fstab.end()) {
            fprintf(stderr, "Unknown partition %s, skipping\n", partition.c_str());
            retval = UNKNOWN_PARTITION;
            continue;
        }
        partitions.emplace_back(*it);
        ++optind;
    }

    // Deal with all partitions case.
    if (partitions.empty() && !retval) {
        for (auto const& entry : fstab) {
            if (remountable_partition(entry) &&
                (std::find_if(partitions.begin(), partitions.end(), [entry](const auto& previous) {
                     return android::base::StartsWith(entry.mount_point, previous.mount_point);
                 }) == partitions.end())) {
                partitions.emplace_back(entry);
            }
        }
    }
    if (partitions.empty()) {
        fprintf(stderr, "No partitions to mount\n");
        return retval;
    }

    // Setup overlayfs backing.
    for (auto const& entry : partitions) {
        auto change = false;
        errno = 0;
        if (fs_mgr_overlayfs_setup(nullptr, entry.mount_point.c_str(), &change)) {
            if (change) {
                fprintf(stderr, "Using overlayfs for %s\n", entry.mount_point.c_str());
            }
        } else if (errno) {
            fprintf(stderr, "Overlayfs setup for %s failed with error %s\n",
                    entry.mount_point.c_str(), strerror(errno));
        }
    }

    // Mount overlayfs.
    fs_mgr_overlayfs_mount_all(&partitions);

    // Remount selected partitions.
    for (auto const& entry : partitions) {
        auto ret = mount(entry.blk_device.c_str(), entry.mount_point.c_str(), entry.fs_type.c_str(),
                         MS_REMOUNT, nullptr);
        if (ret < 0) {
            fprintf(stderr, "failed to remount partition %s with error %s\n",
                    entry.mount_point.c_str(), strerror(errno));
            retval = REMOUNT_FAILED;
        }
    }

    return retval;
}

/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "fs_mgr_dm_linear.h"

#include <dirent.h>
#include <inttypes.h>
#include <linux/dm-ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sstream>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include "fs_mgr_priv.h"
#include "fs_mgr_priv_dm_ioctl.h"

namespace android {
namespace fs_mgr {

std::string PartitionExtent::Serialize() const {
    // Note: we need to include an explicit null-terminator.
    std::string argv =
        android::base::StringPrintf("%s %" PRIu64, block_device_.c_str(), first_sector_);
    argv.push_back(0);

    // The kernel expects each target to be aligned.
    size_t spec_bytes = sizeof(struct dm_target_spec) + argv.size();
    size_t padding = ((spec_bytes + 7) & ~7) - spec_bytes;
    for (size_t i = 0; i < padding; i++) {
        argv.push_back(0);
    }

    struct dm_target_spec spec;
    spec.sector_start = logical_sector_;
    spec.length = num_sectors_;
    spec.status = 0;
    strcpy(spec.target_type, "linear");
    spec.next = sizeof(struct dm_target_spec) + argv.size();

    return std::string((char*)&spec, sizeof(spec)) + argv;
}

static bool LoadDmTable(int dm_fd, const Partition& partition) {
    // Combine all dm_target_spec buffers together.
    std::string target_string;
    for (const PartitionExtent& extent : partition.extents) {
        target_string += extent.Serialize();
    }

    // Allocate the ioctl buffer.
    size_t buffer_size = sizeof(struct dm_ioctl) + target_string.size();
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(buffer_size);

    // Initialize the ioctl buffer header, then copy our target specs in.
    struct dm_ioctl* io = reinterpret_cast<struct dm_ioctl*>(buffer.get());
    fs_mgr_dm_ioctl_init(io, buffer_size, partition.name);
    io->target_count = partition.extents.size();
    if (partition.attributes & kPartitionReadonly) {
        io->flags |= DM_READONLY_FLAG;
    }
    memcpy(io + 1, target_string.c_str(), target_string.size());

    if (ioctl(dm_fd, DM_TABLE_LOAD, io)) {
        PERROR << "Failed ioctl() on DM_TABLE_LOAD, partition " << partition.name;
        return false;
    }
    return true;
}

static bool LoadTablesAndActivate(int dm_fd, const Partition& partition) {
    if (!LoadDmTable(dm_fd, partition)) {
        return false;
    }

    struct dm_ioctl io;
    return fs_mgr_dm_resume_table(&io, partition.name, dm_fd);
}

static bool CreateDmDeviceForPartition(int dm_fd, const Partition& partition) {
    struct dm_ioctl io;
    if (!fs_mgr_dm_create_device(&io, partition.name, dm_fd)) {
        return false;
    }
    if (!LoadTablesAndActivate(dm_fd, partition)) {
        // Remove the device rather than leave it in an inactive state.
        fs_mgr_dm_destroy_device(&io, partition.name, dm_fd);
        return false;
    }

    LINFO << "Created device-mapper device: " << partition.name;
    return true;
}

bool MapLogicalPartitions(const PartitionTable& table) {
    android::base::unique_fd dm_fd(open("/dev/device-mapper", O_RDWR));
    if (dm_fd < 0) {
        PLOG(ERROR) << "failed to open /dev/device-mapper";
        return false;
    }
    for (const auto& partition : table.partitions) {
        if (!CreateDmDeviceForPartition(dm_fd, partition)) {
            LOG(ERROR) << "could not create dm-linear device for partition: " << partition.name;
            return false;
        }
    }
    return true;
}

static bool ReadDtString(const std::string& file, std::string* value) {
    if (!android::base::ReadFileToString(file, value)) {
        return false;
    }
    if (value->empty()) {
        return false;
    }
    // Trim the trailing '\0' out.
    value->resize(value->size() - 1);
    return true;
}

static bool ReadDtUint64(const std::string& file, uint64_t* value) {
    std::string text;
    if (!ReadDtString(file, &text)) {
        return false;
    }
    char* endptr;
    long long int out = strtoll(text.c_str(), &endptr, 10);
    if (endptr == text.c_str() || endptr != text.c_str() + text.size()) {
        return false;
    }
    *value = out;
    return true;
}

static bool ReadPartitionFromDeviceTree(Partition& partition) {
    std::string extent_dir_prefix =
        get_android_dt_dir() + "/logical_partitions/" + partition.name + "/extent@";

    uint64_t current_sector = 0;
    for (unsigned index = 0;; index++) {
        std::string extent_dir =
            android::base::StringPrintf("%s%d", extent_dir_prefix.c_str(), index);
        if (access(extent_dir.c_str(), F_OK)) {
            break;
        }

        uint64_t first_sector, num_sectors;
        std::string block_device;

        std::string file_name = extent_dir + "/block_device";
        if (!ReadDtString(file_name, &block_device)) {
            LERROR << "dm_linear_dt: block_device missing, partition " << partition.name;
            return false;
        }

        file_name = extent_dir + "/first_sector";
        if (!ReadDtUint64(file_name, &first_sector)) {
            LERROR << "dm_linear_dt: first_sector missing, partition " << partition.name;
            return false;
        }

        file_name = extent_dir + "/num_sectors";
        if (!ReadDtUint64(file_name, &num_sectors)) {
            LERROR << "dm_linear_dt: num_sectors missing, partition " << partition.name;
            return false;
        }

        PartitionExtent extent(current_sector, first_sector, num_sectors, block_device);
        partition.extents.push_back(extent);

        current_sector += num_sectors;
    }

    if (partition.extents.empty()) {
        LERROR << "dm_linear_dt: Failed to find any extents for " << partition.name;
        return false;
    }
    return true;
}

std::unique_ptr<PartitionTable> LoadPartitionsFromDeviceTree() {
    if (!is_dt_compatible()) return nullptr;

    std::string dt_dir = get_android_dt_dir() + "/logical_partitions";
    std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(dt_dir.c_str()), closedir);
    if (!dir) {
        return nullptr;
    }

    std::unique_ptr<PartitionTable> table = std::make_unique<PartitionTable>();

    while (dirent* dp = readdir(dir.get())) {
        // Skip over name, compatible, and .
        if (dp->d_type != DT_DIR || dp->d_name[0] == '.') {
            continue;
        }

        Partition partition;
        partition.name = dp->d_name;
        if (!ReadPartitionFromDeviceTree(partition)) {
            return nullptr;
        }
        table->partitions.push_back(partition);
    }
    return table;
}

}  // namespace fs_mgr
}  // namespace android

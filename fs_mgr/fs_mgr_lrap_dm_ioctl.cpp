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

#include <android-base/logging.h>
#include <linux/dm-ioctl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sstream>
#include <vector>
#include "fs_mgr_lrap.h"
#include "fs_mgr_priv.h"

namespace android {
namespace lrap {

static void InitDmIoctl(struct dm_ioctl* io, size_t size, const Partition* partition, int flags) {
    memset(io, 0, sizeof(*io));
    io->data_size = size;
    io->data_start = sizeof(struct dm_ioctl);
    io->version[0] = 4;
    io->version[1] = 0;
    io->version[2] = 0;
    io->flags = flags;
    strlcpy(io->name, partition->name.c_str(), sizeof(io->name));
}

static bool CreateDmDevice(int dm_fd, const Partition* partition, dev_t* device) {
    int flags = 0;
    if (partition->attributes & kPartitionReadonly) {
        flags |= DM_READONLY_FLAG;
    }

    struct dm_ioctl io;
    InitDmIoctl(&io, sizeof(io), partition, flags);
    if (ioctl(dm_fd, DM_DEV_CREATE, &io)) {
        PERROR << "Failed ioctl() on DM_DEV_CREATE " << partition->name;
        return false;
    }

    *device = io.dev;
    return true;
}

static bool LoadDmTable(int dm_fd, const Partition* partition) {
    std::vector<std::string> targets;

    // First compute how many bytes are needed for our dm_target_spec list.
    size_t bytes_needed = sizeof(struct dm_ioctl);
    for (size_t i = 0; i < partition->num_extents; i++) {
        const PartitionExtent& extent = partition->extents[i];
        std::stringstream argv_builder;
        argv_builder << extent.block_device << " " << extent.first_sector;

        std::string argv = argv_builder.str();
        targets.push_back(argv);

        // Add the required target size, plus alignment for the next target.
        bytes_needed += (sizeof(struct dm_target_spec) + argv.size() + 1);
        bytes_needed = (bytes_needed + 7) & ~size_t(7);
    }

    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(bytes_needed);

    struct dm_ioctl* io = reinterpret_cast<struct dm_ioctl*>(buffer.get());
    InitDmIoctl(io, bytes_needed, partition, 0);

    struct dm_target_spec* spec = reinterpret_cast<struct dm_target_spec*>(io + 1);
    uint64_t current_sector = 0;
    for (size_t i = 0; i < partition->num_extents; i++) {
        const PartitionExtent& extent = partition->extents[i];
        const std::string& argv = targets[i];

        spec->sector_start = current_sector;
        spec->length = extent.num_sectors;
        spec->status = 0;
        spec->next = (sizeof(struct dm_target_spec) + argv.size() + 1);
        spec->next = (spec->next + 7) & ~7;
        strcpy(spec->target_type, "linear");
        memcpy(spec + 1, argv.c_str(), argv.size() + 1);
        spec =
            reinterpret_cast<struct dm_target_spec*>(reinterpret_cast<uint8_t*>(spec) + spec->next);
        io->target_count++;
    }
    assert((void*)spec == (void*)(buffer.get() + bytes_needed));

    if (ioctl(dm_fd, DM_TABLE_LOAD, io)) {
        PERROR << "Failed ioctl() on DM_TABLE_LOAD, partition " << partition->name;
        return false;
    }
    return true;
}

static bool LoadTablesAndActivate(int dm_fd, const Partition* partition) {
    if (!LoadDmTable(dm_fd, partition)) {
        return false;
    }

    struct dm_ioctl io;
    InitDmIoctl(&io, sizeof(io), partition, 0);
    if (ioctl(dm_fd, DM_DEV_SUSPEND, &io)) {
        PERROR << "Failed ioctl() on DM_DEV_SUSPEND, partition " << partition->name;
        return false;
    }
    return true;
}

static bool RemoveDevice(int dm_fd, const Partition* partition) {
    struct dm_ioctl io;
    InitDmIoctl(&io, sizeof(io), partition, 0);
    if (ioctl(dm_fd, DM_DEV_REMOVE, &io)) {
        PERROR << "Failed ioctl() on DM_DEV_REMOVE, partition " << partition->name;
        return false;
    }
    return true;
}

bool CreateDmDeviceForPartition(int dm_fd, const Partition* partition) {
    dev_t device;
    if (!CreateDmDevice(dm_fd, partition, &device)) {
        return false;
        ;
    }
    if (!LoadTablesAndActivate(dm_fd, partition)) {
        // Remove the device rather than leave it in an inactive state.
        RemoveDevice(dm_fd, partition);
        return false;
    }

    std::string named_device = std::string("/dev/block/dm-") + partition->name;
    if (mknod(named_device.c_str(), S_IFBLK | 0600, device)) {
        PERROR << "mknod() failed creating device node " << named_device;
        RemoveDevice(dm_fd, partition);
        return false;
    }

    LINFO << "Created device-mapper device: " << partition->name;
    return true;
}

}  // namespace lrap
}  // namespace android

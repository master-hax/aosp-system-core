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

#ifndef __CORE_FS_MGR_DM_LINEAR_H
#define __CORE_FS_MGR_DM_LINEAR_H

#include <stdint.h>
#include <memory>
#include <string>
#include <vector>

namespace android {
namespace fs_mgr {

static const uint32_t kPartitionReadonly = 0x1;

struct PartitionExtent {
    // Logical sector this extent represents in the presented block device.
    // This is equal to the previous extent's logical sector plus the number
    // of sectors in that extent. The first extent always starts at 0.
    uint64_t logical_sector;
    // First 512-byte sector of this extent, on the source block device.
    uint64_t first_sector;
    // Number of 512-byte sectors.
    uint64_t num_sectors;
    // Target block device.
    std::string block_device;

    // Return a string containing the dm_target_spec buffer needed to use this
    // extent in a device-mapper table.
    std::string Serialize() const;
};

struct Partition {
    Partition() : attributes(0), num_sectors(0) {}

    std::string name;
    uint32_t attributes;
    // Number of 512-byte sectors total.
    uint64_t num_sectors;
    // List of extents.
    std::vector<PartitionExtent> extents;
};

struct PartitionTable {
    // List of partitions in the partition table.
    std::vector<Partition> partitions;
};

// Load a dm-linear table from the device tree if one is available; otherwise,
// return null.
std::unique_ptr<PartitionTable> LoadPartitionsFromDeviceTree();

// Create a device-mapper device for the given partition table entry.
//
// On success, two devices nodes will be created, both pointing to the same
// device:
//   /dev/block/dm-<N> where N is a sequential ID assigned by device-mapper.
//   /dev/block/dm-<name> where |name| is the partition name.
//
// |dm_fd| must be an open descriptor to the device-mapper device with read-
// write privileges.
//
// |partition| must be a valid fs_mgr::Partition with one or more extents.
bool CreateDmDeviceForPartition(int dm_fd, const Partition& partition);

}  // namespace fs_mgr
}  // namespace android

#endif  // __CORE_FS_MGR_DM_LINEAR_H

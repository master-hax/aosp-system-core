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

#ifndef __CORE_FS_MGR_LRAP_H
#define __CORE_FS_MGR_LRAP_H

#include <stdint.h>
#include <memory>
#include <string>

namespace android {
namespace lrap {

static const uint32_t kPartitionReadonly = 0x1;

struct PartitionExtent {
    // First 512-byte sector of this extent, on the target block device.
    uint64_t first_sector;
    // Number of 512-byte sectors.
    uint64_t num_sectors;
    // Target block device.
    const char* block_device;
};

struct Partition {
    Partition() : attributes(0), num_sectors(0), num_extents(0) {}

    std::string name;
    uint32_t attributes;
    // Number of 512-byte sectors total.
    uint64_t num_sectors;
    // List of extents.
    uint32_t num_extents;
    std::unique_ptr<PartitionExtent[]> extents;
};

struct PartitionTable {
    PartitionTable() : num_partitions(0), num_block_devices(0) {}

    // List of partitions in the partition table.
    uint32_t num_partitions;
    std::unique_ptr<Partition[]> partitions;

    // List of source block devices.
    uint32_t num_block_devices;
    std::unique_ptr<std::string[]> block_devices;
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
// |partition| must be a valid lrap::Partition with one or more extents.
bool CreateDmDeviceForPartition(int dm_fd, const Partition* partition);

}  // namespace lrap
}  // namespace android

#endif  // __CORE_FS_MGR_LRAP_H

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

#include <errno.h>
#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <vector>

#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include "dm.h"

namespace android {
namespace dm {

DeviceMapper& DeviceMapper::Instance(bool cleanup) {
    static DeviceMapper instance(cleanup);
    return instance;
}

DeviceMapper::~DeviceMapper() {
    if (fd_ == -1) {
        return;
    }

    std::unique_ptr<struct dm_ioctl, decltype(&free)> io(
            static_cast<struct dm_ioctl*>(malloc(sizeof(struct dm_ioctl))), free);
    if (io == nullptr) {
        LOG(ERROR) << "Failed to allocate memory. Possibly leaking : "
                   << ::android::base::Join(devices_, ",");
        return;
    }

    // List that tracks the not-suspended devices here
    std::vector<std::string> active_devs;
    for (auto dev = devices_.begin(); dev != devices_.end();) {
        if (!DevGetStatus(io.get(), *dev)) {
            // failed to read the status of the device, nothing we can do here.
            LOG(ERROR) << "Failed to get the status of dm-" << *dev;
            ++dev;
            continue;
        }

        // - For each device we created, check if the device is active.
        //   If yes,
        //   - Check if the device is suspended, warn if yes, and skip
        //     to the next device in the list.
        //
        //   If no,
        //   - continue to check another device.
        if (io->flags & DM_ACTIVE_PRESENT_FLAG) {
            if (io->flags & DM_SUSPEND_FLAG) {
                LOG(ERROR) << "Leaking suspended dm device [" << *dev << "] open:" << io->open_count
                           << " targets:" << io->target_count;
                ++dev;
                continue;
            }
            // Add to a separate list to check against our own at the end
            active_devs.push_back(*dev);
            ++dev;
        } else {
            if (!DeleteDevice(*dev)) {
                LOG(ERROR) << "Leaking dm device [" << *dev << "], failed to delete";
                ++dev;
                continue;
            }
            // Remove from internal list, it will be checked for active devices at the end
            dev = devices_.erase(dev);
        }
    }

    // If we leak devices, consider it to be FATAL.
    CHECK(active_devs == devices_) << "Leaked device mapper devices";

    ::close(fd_);
}

// Creates a new device mapper device
bool DeviceMapper::CreateDevice(const std::string& name) {
    if (name.empty()) {
        LOG(ERROR) << "Unnamed device mapper device creation is not supported";
        return false;
    }

    if (name.size() >= DM_NAME_LEN) {
        LOG(ERROR) << "[" << name << "] is too long to be device mapper name";
        return false;
    }

    std::unique_ptr<struct dm_ioctl, decltype(&free)> io(
            static_cast<struct dm_ioctl*>(malloc(sizeof(struct dm_ioctl))), free);
    if (io == nullptr) {
        LOG(ERROR) << "Failed to allocate dm_ioctl";
        return false;
    }
    InitIo(io.get(), name);

    if (ioctl(fd_, DM_DEV_CREATE, io.get())) {
        PLOG(ERROR) << "DM_DEV_CREATE failed for [" << name << "]";
        return false;
    }

    // Check to make sure the newly created device doesn't already have targets
    // added or opened by someone
    CHECK(io->target_count == 0) << "Unexpected targets for newly created [" << name << "] device";
    CHECK(io->open_count == 0) << "Unexpected opens for newly created [" << name << "] device";

    // add the device to own list to track their deletion if we are configured
    // for the same
    if (cleanup_) devices_.push_back(name);
    return true;
}

bool DeviceMapper::DeleteDevice(const std::string& name) {
    if (name.empty()) {
        LOG(ERROR) << "Unnamed device mapper device creation is not supported";
        return false;
    }

    if (name.size() >= DM_NAME_LEN) {
        LOG(ERROR) << "[" << name << "] is too long to be device mapper name";
        return false;
    }

    std::unique_ptr<struct dm_ioctl, decltype(&free)> io(
            static_cast<struct dm_ioctl*>(malloc(sizeof(struct dm_ioctl))), free);
    if (io == nullptr) {
        LOG(ERROR) << "Failed to allocate dm_ioctl";
        return false;
    }
    InitIo(io.get(), name);

    if (ioctl(fd_, DM_DEV_REMOVE, io.get())) {
        PLOG(ERROR) << "DM_DEV_REMOVE failed for [" << name << "]";
        return false;
    }

    // Check to make sure appropriate uevent is generated so ueventd will
    // do the right thing and remove the corresponding device node and symlinks.
    CHECK(io->flags & DM_UEVENT_GENERATED_FLAG)
            << "Didn't generate uevent for [" << name << "] removal";

    return true;
}

const std::unique_ptr<DmTable> DeviceMapper::table(const std::string& /* name */) const {
    // TODO(b/110035986): Return the table, as read from the kernel instead
    return nullptr;
}

DmDeviceState DeviceMapper::state(const std::string& /* name */) const {
    // TODO(b/110035986): Return the state, as read from the kernel instead
    return DmDeviceState::INVALID;
}

bool DeviceMapper::LoadTableAndActivate(const std::string& /* name */, const DmTable& /* table */) {
    return false;
}

// Reads all the available device mapper targets and their corresponding
// versions from the kernel and returns in a vector
bool DeviceMapper::GetAvailableTargets(std::vector<DmTarget>* targets) {
    targets->clear();

    // calculate the space needed to read a maximum of kMaxPossibleDmTargets
    uint32_t payload_size = sizeof(struct dm_target_versions);
    payload_size += DM_MAX_TYPE_NAME;
    // device mapper wants every target spec to be aligned at 8-byte boundary
    payload_size = DM_ALIGN(payload_size);
    payload_size *= kMaxPossibleDmTargets;

    uint32_t data_size = sizeof(struct dm_ioctl) + payload_size;
    auto buffer = std::unique_ptr<void, void (*)(void*)>(calloc(1, data_size), free);
    if (buffer == nullptr) {
        LOG(ERROR) << "failed to allocate memory";
        return false;
    }

    // Sets appropriate data size and data_start to make sure we tell kernel
    // about the total size of the buffer we are passing and where to start
    // writing the list of targets.
    struct dm_ioctl* io = reinterpret_cast<struct dm_ioctl*>(buffer.get());
    InitIo(io);
    io->data_size = data_size;
    io->data_start = sizeof(*io);

    if (ioctl(fd_, DM_LIST_VERSIONS, io)) {
        PLOG(ERROR) << "DM_LIST_VERSIONS failed";
        return false;
    }

    // If the provided buffer wasn't enough to list all targets, note that
    // any data beyond sizeof(*io) must not be read in this case
    if (io->flags & DM_BUFFER_FULL_FLAG) {
        LOG(INFO) << data_size << " is not enough memory to list all dm targets";
        return false;
    }

    // if there are no targets registered, return success with empty vector
    if (io->data_size == sizeof(*io)) {
        return true;
    }

    // Parse each target and list the name and version
    // TODO(b/110035986): Templatize this
    uint32_t next = sizeof(*io);
    data_size = io->data_size - next;
    struct dm_target_versions* vers =
            reinterpret_cast<struct dm_target_versions*>(static_cast<char*>(buffer.get()) + next);
    while (next && data_size) {
        targets->emplace_back((vers));
        if (vers->next == 0) {
            break;
        }
        next += vers->next;
        data_size -= vers->next;
        vers = reinterpret_cast<struct dm_target_versions*>(static_cast<char*>(buffer.get()) + next);
    }

    return true;
}

bool DeviceMapper::GetAvailableDevices(std::vector<DmBlockDevice>* devices) {
    devices->clear();

    // calculate the space needed to read a maximum of 256 targets, each with
    // name with maximum length of 16 bytes
    uint32_t payload_size = sizeof(struct dm_name_list);
    // 128-bytes for the name
    payload_size += DM_NAME_LEN;
    // dm wants every device spec to be aligned at 8-byte boundary
    payload_size = DM_ALIGN(payload_size);
    payload_size *= kMaxPossibleDmDevices;
    uint32_t data_size = sizeof(struct dm_ioctl) + payload_size;
    auto buffer = std::unique_ptr<void, void (*)(void*)>(calloc(1, data_size), free);
    if (buffer == nullptr) {
        LOG(ERROR) << "failed to allocate memory";
        return false;
    }

    // Sets appropriate data size and data_start to make sure we tell kernel
    // about the total size of the buffer we are passing and where to start
    // writing the list of targets.
    struct dm_ioctl* io = reinterpret_cast<struct dm_ioctl*>(buffer.get());
    InitIo(io);
    io->data_size = data_size;
    io->data_start = sizeof(*io);

    if (ioctl(fd_, DM_LIST_DEVICES, io)) {
        PLOG(ERROR) << "DM_LIST_DEVICES failed";
        return false;
    }

    // If the provided buffer wasn't enough to list all devices any data
    // beyond sizeof(*io) must not be read.
    if (io->flags & DM_BUFFER_FULL_FLAG) {
        LOG(INFO) << data_size << " is not enough memory to list all dm devices";
        return false;
    }

    // if there are no devices created yet, return success with empty vector
    if (io->data_size == sizeof(*io)) {
        return true;
    }

    // Parse each device and add a new DmBlockDevice to the vector
    // created from the kernel data.
    uint32_t next = sizeof(*io);
    data_size = io->data_size - next;
    struct dm_name_list* dm_dev =
            reinterpret_cast<struct dm_name_list*>(static_cast<char*>(buffer.get()) + next);

    while (next && data_size) {
        devices->emplace_back((dm_dev));
        if (dm_dev->next == 0) {
            break;
        }
        next += dm_dev->next;
        data_size -= dm_dev->next;
        dm_dev = reinterpret_cast<struct dm_name_list*>(static_cast<char*>(buffer.get()) + next);
    }

    return true;
}

// Accepts a device mapper device name (like system_a, vendor_b etc) and
// returns the path to it's device node (or symlink to the device node)
std::string DeviceMapper::GetDmDevicePathByName(const std::string& /* name */) {
    return "";
}

// private methods of DeviceMapper
void DeviceMapper::InitIo(struct dm_ioctl* io, const std::string& name) const {
    CHECK(io != nullptr) << "nullptr passed to dm_ioctl initialization";
    memset(io, 0, sizeof(*io));

    io->version[0] = DM_VERSION0;
    io->version[1] = DM_VERSION1;
    io->version[2] = DM_VERSION2;
    io->data_size = sizeof(*io);
    io->data_start = 0;
    if (!name.empty()) {
        strlcpy(io->name, name.c_str(), sizeof(io->name));
    }
}

bool DeviceMapper::DevGetStatus(struct dm_ioctl* io, const std::string& name) const {
    CHECK(io != nullptr) << "nullptr passed to DevGetStatus";
    CHECK(!name.empty());
    InitIo(io, name);
    if (ioctl(fd_, DM_DEV_STATUS, io)) {
        PLOG(ERROR) << "DM_DEV_STATUS Failed for [" << name << "]";
        return false;
    }

    return true;
}

}  // namespace dm
}  // namespace android

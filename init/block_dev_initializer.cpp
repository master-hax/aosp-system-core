// Copyright (C) 2020 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <chrono>
#include <string_view>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <fs_mgr.h>

#include "block_dev_initializer.h"

namespace android {
namespace init {

using android::base::Timer;
using namespace std::chrono_literals;

BlockDevInitializer::BlockDevInitializer() : uevent_listener_(16 * 1024 * 1024) {
    device_handler_ = std::make_unique<DeviceHandler>(std::vector<Permissions>{},
                                                      std::vector<SysfsPermissions>{},
                                                      std::vector<Subsystem>{}, false);
}

bool BlockDevInitializer::InitDeviceMapper() {
    return InitMiscDevice("device-mapper");
}

bool BlockDevInitializer::InitDmUser(const std::string& name) {
    return InitMiscDevice("dm-user!" + name);
}

bool BlockDevInitializer::InitMiscDevice(const std::string& name) {
    const std::string dm_path = "/devices/virtual/misc/" + name;
    bool found = false;
    auto dm_callback = [this, &dm_path, &found](const Uevent& uevent) {
        if (uevent.path == dm_path) {
            device_handler_->HandleUevent(uevent);
            found = true;
            return ListenerAction::kStop;
        }
        return ListenerAction::kContinue;
    };
    uevent_listener_.RegenerateUeventsForPath("/sys" + dm_path, dm_callback);
    if (!found) {
        LOG(INFO) << name << " device not found in /sys, waiting for its uevent";
        Timer t;
        uevent_listener_.Poll(dm_callback, 10s);
        LOG(INFO) << "Wait for " << name << " returned after " << t;
    }
    if (!found) {
        LOG(ERROR) << name << " device not found after polling timeout";
        return false;
    }
    return true;
}

ListenerAction BlockDevInitializer::HandleUevent(const Uevent& uevent,
                                                 std::set<std::string>* devices) {
    // Ignore everything that is not a block device.
    if (uevent.subsystem != "block") {
        return ListenerAction::kContinue;
    }

    auto name = uevent.partition_name;
    if (name.empty()) {
        size_t base_idx = uevent.path.rfind('/');
        if (base_idx == std::string::npos) {
            return ListenerAction::kContinue;
        }
        name = uevent.path.substr(base_idx + 1);
    }

    auto iter = devices->find(name);
    if (iter == devices->end()) {
        auto partition_name = DeviceHandler::GetPartitionNameForDevice(uevent.device_name);
        if (!partition_name.empty()) {
            iter = devices->find(partition_name);
        }
        if (iter == devices->end()) {
            return ListenerAction::kContinue;
        }
    }

    LOG(VERBOSE) << __PRETTY_FUNCTION__ << ": found partition: " << name;

    // Remove partition from the list only if it was found on boot device
    if (device_handler_->IsBootDevice(uevent)) {
        devices->erase(iter);
    }

    device_handler_->HandleUevent(uevent);
    return devices->empty() ? ListenerAction::kStop : ListenerAction::kContinue;
}

bool BlockDevInitializer::InitDevices(std::set<std::string> devices) {
    bool uuid_check_done;

    auto boot_part_callback = [&, this](const Uevent& uevent) -> ListenerAction {
        uuid_check_done = device_handler_->CheckUeventForBootPartUuid(uevent);
        return uuid_check_done ? ListenerAction::kStop : ListenerAction::kContinue;
    };

    // Re-run already arrived uevents looking for the boot partition UUID.
    // NOTE: If we're not using the boot partition UUID to find the boot
    // device then the first uevent we analyze will cause us to stop looking
    // and set `uuid_check_done`.
    uevent_listener_.RegenerateUevents(boot_part_callback);

    // If we haven't found it yet, poll for uevents for longer
    if (!uuid_check_done) {
        Timer t;
        uevent_listener_.Poll(boot_part_callback, 10s);
        LOG(INFO) << "Wait for boot partition returned after " << t;
    }

    // Give a nicer error message if we were expecting to find the kernel boot
    // partition but didn't. Later code would check too but the message there
    // is a bit further from the root cause of the problem.
    if (!uuid_check_done) {
        LOG(ERROR) << __PRETTY_FUNCTION__ << ": boot partition not found after polling timeout.";
        return false;
    }

    // At this point we either found the boot partition UUID and used that to
    // set the boot device or we weren't using the boot partition UUID and
    // we'll rely on the bootloader having set the boot device. Now wait for
    // all the partitions on the boot device to show up.

    auto uevent_callback = [&, this](const Uevent& uevent) -> ListenerAction {
        return HandleUevent(uevent, &devices);
    };
    uevent_listener_.RegenerateUevents(uevent_callback);

    // UeventCallback() will remove found partitions from |devices|. So if it
    // isn't empty here, it means some partitions are not found.
    if (!devices.empty()) {
        LOG(INFO) << __PRETTY_FUNCTION__
                  << ": partition(s) not found in /sys, waiting for their uevent(s): "
                  << android::base::Join(devices, ", ");
        Timer t;
        uevent_listener_.Poll(uevent_callback, 10s);
        LOG(INFO) << "Wait for partitions returned after " << t;
    }

    if (!devices.empty()) {
        LOG(ERROR) << __PRETTY_FUNCTION__ << ": partition(s) not found after polling timeout: "
                   << android::base::Join(devices, ", ");
        return false;
    }
    return true;
}

// Creates "/dev/block/dm-XX" for dm nodes by running coldboot on /sys/block/dm-XX.
bool BlockDevInitializer::InitDmDevice(const std::string& device) {
    const std::string device_name(basename(device.c_str()));
    const std::string syspath = "/sys/block/" + device_name;
    return InitDevice(syspath, device_name);
}

bool BlockDevInitializer::InitPlatformDevice(const std::string& dev_name) {
    return InitDevice("/sys/devices/platform", dev_name);
}

bool BlockDevInitializer::InitHvcDevice(const std::string& dev_name) {
    return InitDevice("/sys/devices/virtual/tty", dev_name);
}

bool BlockDevInitializer::InitDevice(const std::string& syspath, const std::string& device_name) {
    bool found = false;

    auto uevent_callback = [&device_name, this, &found](const Uevent& uevent) {
        if (uevent.device_name == device_name) {
            LOG(VERBOSE) << "Creating device : " << device_name;
            device_handler_->HandleUevent(uevent);
            found = true;
            return ListenerAction::kStop;
        }
        return ListenerAction::kContinue;
    };

    uevent_listener_.RegenerateUeventsForPath(syspath, uevent_callback);
    if (!found) {
        LOG(INFO) << "device '" << device_name << "' not found in /sys, waiting for its uevent";
        Timer t;
        uevent_listener_.Poll(uevent_callback, 10s);
        LOG(INFO) << "wait for device '" << device_name << "' returned after " << t;
    }
    if (!found) {
        LOG(ERROR) << "device '" << device_name << "' not found after polling timeout";
        return false;
    }
    return true;
}

}  // namespace init
}  // namespace android

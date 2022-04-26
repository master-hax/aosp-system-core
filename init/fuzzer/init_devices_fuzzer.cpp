/*
 * Copyright (C) 2022 The Android Open Source Project
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
#include <devices.h>
#include <fs_mgr.h>
#include <private/android_filesystem_config.h>
#include <selabel.h>
#include <uevent.h>
#include <fstream>
#include "fuzzer/FuzzedDataProvider.h"

using namespace android;
using namespace android::init;

constexpr int32_t kMaxStringLength = 100;
constexpr int32_t kMinIterations = 3;
constexpr int32_t kMaxIterations = 20;
constexpr int32_t kMinDevVal = 1;
constexpr int32_t kMaxDevVal = 128;
constexpr int32_t kPermissionType[] = {0660, 0440, 0600, 0700, 0777, 0755};
constexpr int32_t kGroupId[] = {AID_RADIO, AID_INPUT, AID_LOG};
const std::string kAttribute[] = {"enable", "trusty_version", "poll_delay"};
const std::string kAction[] = {"add", "change", "bind", "online", "remove"};
const std::string kSubsystem[] = {"block", "usb", "misc"};
const std::string kDeviceName[] = {"ashmem", "dm-user"};
const std::string kdevice_paths[] = {
        "/devices/platform/soc/soc:",
        "/devices/pci0000:00/0000:00:1f.2/",
        "/devices/vbd-1234/",
        "/devices/virtual/block/dm-",
};
const std::string kValidPaths[] = {
        "/sys/bus/platform/devices/soc:*", "/sys/devices/virtual/block/dm-*",
        "/sys/bus/i2c/devices/i2c-*",      "/sys/devices/virtual/input/input*",
        "/sys/class/input/event*",         "/sys/class/input/input*",
};

class InitDeviceFuzzer {
  public:
    InitDeviceFuzzer(const uint8_t* data, size_t size) : fdp_(data, size){};
    void InvokeDevice();

  private:
    FuzzedDataProvider fdp_;
};

Uevent getUevent(FuzzedDataProvider* fdp) {
    Uevent uevent;
    uevent.action = fdp->PickValueInArray(kAction);
    const std::string device_path = fdp->PickValueInArray(kdevice_paths);
    uevent.path = device_path + fdp->ConsumeRandomLengthString(kMaxStringLength);
    uevent.subsystem = fdp->ConsumeBool() ? fdp->ConsumeRandomLengthString(kMaxStringLength)
                                          : fdp->PickValueInArray(kSubsystem);
    uevent.firmware = fdp->ConsumeBool() ? fdp->ConsumeRandomLengthString(kMaxStringLength) : "";
    uevent.modalias = fdp->ConsumeBool() ? fdp->ConsumeRandomLengthString(kMaxStringLength) : "";
    uevent.partition_name =
            fdp->ConsumeBool() ? fdp->ConsumeRandomLengthString(kMaxStringLength) : "";
    uevent.device_name = fdp->ConsumeBool() ? fdp->PickValueInArray(kDeviceName) : "";
    uevent.partition_num = 1;
    uevent.major = fdp->ConsumeIntegralInRange(kMinDevVal, kMaxDevVal);
    uevent.minor = fdp->ConsumeIntegralInRange(kMinDevVal, kMaxDevVal);
    return uevent;
}

void InitDeviceFuzzer::InvokeDevice() {
    Uevent uevent = getUevent(&fdp_);
    std::vector<SysfsPermissions> sys_fs_permissions;
    std::vector<Permissions> device_permissions;
    std::vector<Subsystem> sub_systems;
    std::set<std::string> boot_devices = android::fs_mgr::GetBootDevices();
    int32_t count = 0;
    int32_t number_iteration = fdp_.ConsumeIntegralInRange(kMinIterations, kMaxIterations);
    while (++count < number_iteration) {
        mode_t perm = fdp_.PickValueInArray(kPermissionType);
        uid_t uid = fdp_.ConsumeBool() ? AID_ROOT : AID_SYSTEM;
        gid_t gid = fdp_.PickValueInArray(kGroupId);
        auto device_param = fdp_.PickValueInArray<const std::function<void()>>({
                [&]() {
                    const std::string name = fdp_.PickValueInArray(kValidPaths);
                    const std::string attribute = fdp_.PickValueInArray(kAttribute);
                    SysfsPermissions permissions(name, attribute, perm, uid, gid,
                                                 fdp_.ConsumeBool());
                    sys_fs_permissions.emplace_back(permissions);
                },
                [&]() {
                    Permissions permissions("/dev/device*name*", perm, uid, gid,
                                            fdp_.ConsumeBool());
                    device_permissions.emplace_back(permissions);
                },
                [&]() {
                    const std::string device_name =
                            fdp_.ConsumeRandomLengthString(kMaxStringLength);
                    android::init::Subsystem::DevnameSource source =
                            fdp_.ConsumeBool() ? android::init::Subsystem::DEVNAME_UEVENT_DEVNAME
                                               : android::init::Subsystem::DEVNAME_UEVENT_DEVPATH;
                    Subsystem subsys(device_name, source, "/dev");
                    sub_systems.emplace_back(subsys);
                },
        });
        device_param();
    }

    if (device_permissions.size() > 0 && sys_fs_permissions.size() > 0 && sub_systems.size() > 0) {
        DeviceHandler deviceHandler(device_permissions, sys_fs_permissions, sub_systems,
                                    boot_devices, fdp_.ConsumeBool());
        deviceHandler.HandleUevent(uevent);
    }
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
    (void)argc;
    (void)argv;
    SelabelInitialize();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    InitDeviceFuzzer initDeviceFuzzer(data, size);
    initDeviceFuzzer.InvokeDevice();
    return 0;
}

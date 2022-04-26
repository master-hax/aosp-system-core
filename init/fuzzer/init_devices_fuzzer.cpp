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
const std::string kDevicePaths[] = {
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
    InitDeviceFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void invokeDevice();

  private:
    FuzzedDataProvider mFdp;
};

Uevent getUevent(FuzzedDataProvider* fdp) {
    Uevent uevent;
    uevent.action = fdp->PickValueInArray(kAction);
    const std::string devicePath = fdp->PickValueInArray(kDevicePaths);
    uevent.path = devicePath + fdp->ConsumeRandomLengthString(kMaxStringLength);
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

void InitDeviceFuzzer::invokeDevice() {
    Uevent uevent = getUevent(&mFdp);
    std::vector<SysfsPermissions> sysfsPermissions;
    std::vector<Permissions> devPermissions;
    std::vector<Subsystem> subSystems;
    std::set<std::string> bootDevices = android::fs_mgr::GetBootDevices();
    int32_t count = 0;
    int32_t numIteration = mFdp.ConsumeIntegralInRange(kMinIterations, kMaxIterations);
    while (++count < numIteration) {
        mode_t perm = mFdp.PickValueInArray(kPermissionType);
        uid_t uid = mFdp.ConsumeBool() ? AID_ROOT : AID_SYSTEM;
        gid_t gid = mFdp.PickValueInArray(kGroupId);
        auto fillDeviceParam = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() {
                    const std::string name = mFdp.PickValueInArray(kValidPaths);
                    const std::string attribute = mFdp.PickValueInArray(kAttribute);
                    SysfsPermissions permissions(name, attribute, perm, uid, gid,
                                                 mFdp.ConsumeBool());
                    sysfsPermissions.emplace_back(permissions);
                },
                [&]() {
                    Permissions permissions("/dev/device*name*", perm, uid, gid,
                                            mFdp.ConsumeBool());
                    devPermissions.emplace_back(permissions);
                },
                [&]() {
                    const std::string devName = mFdp.ConsumeRandomLengthString(kMaxStringLength);
                    android::init::Subsystem::DevnameSource source =
                            mFdp.ConsumeBool() ? android::init::Subsystem::DEVNAME_UEVENT_DEVNAME
                                               : android::init::Subsystem::DEVNAME_UEVENT_DEVPATH;
                    Subsystem subsys(devName, source, "/dev");
                    subSystems.emplace_back(subsys);
                },
        });
        fillDeviceParam();
    }

    if (devPermissions.size() > 0 && sysfsPermissions.size() > 0 && subSystems.size() > 0) {
        DeviceHandler deviceHandler(devPermissions, sysfsPermissions, subSystems, bootDevices,
                                    mFdp.ConsumeBool());
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
    initDeviceFuzzer.invokeDevice();
    return 0;
}

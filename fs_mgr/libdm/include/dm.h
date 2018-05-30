/*
 *  Copyright 2018 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef _LIBDM_DM_H_
#define _LIBDM_DM_H_

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <memory>

#include <android-base/logging.h>

#include <dm_device.h>

#define DM_ALIGN_MASK (7)
#define DM_ALIGN(x) ((x + DM_ALIGN_MASK) & ~DM_ALIGN_MASK)

namespace android {
namespace dm {

class DeviceMapper final {
  public:
    // Creates a device mapper device with given name. If a device mapper device
    // with the name already exists, return a 'nullptr', otherwise returns a
    // DmDevice object that is suspended.
    DmDevice* CreateDevice(const std::string& name);

    // Removes a device mapper device with the given name.
    // Returns 'true' on success, false otherwise.
    bool DeleteDevice(DmDevice* dev);

    // Returns true if a list of available device mapper targets registered in the kernel was
    // successfully read and stored in 'targets'. Returns 'false' otherwise.
    bool GetAvailableTargets(std::vector<DmTarget>* targets);

    // Returns the path to the device mapper device node in '/dev' corresponding to
    // 'name'.
    std::string GetDmDevicePathByName(const std::string& name);

    // Same as 'GetDmDevicePathByName', except this returns a handle to the 'DmDevice'
    // object corresponding to 'name'.
    DmDevice* Find(const std::string& name);

    // The only way to create a DeviceMapper object.
    static DeviceMapper& Instance();

    ~DeviceMapper() {
        if (fd_ != -1) {
            ::close(fd_);
        }
    }

  private:
    DeviceMapper() : fd_(-1) {
        fd_ = TEMP_FAILURE_RETRY(open("/dev/device-mapper", O_RDWR | O_CLOEXEC));
        if (fd_ < 0) {
            PLOG(ERROR) << "Failed to open device-mapper";
        }
    }

    int fd_;
    // Non-copyable & Non-movable
    DeviceMapper(const DeviceMapper&) = delete;
    DeviceMapper& operator=(const DeviceMapper&) = delete;
    DeviceMapper& operator=(DeviceMapper&&) = delete;
    DeviceMapper(DeviceMapper&&) = delete;
};

}  // namespace dm
}  // namespace android

#endif /* _LIBDM_DM_H_ */

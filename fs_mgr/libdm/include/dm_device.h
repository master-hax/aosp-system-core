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

#ifndef _LIBDM_DMDEVICE_H_
#define _LIBDM_DMDEVICE_H_

#include <string>

#include "dm_table.h"

namespace android {
namespace dm {

enum class DmDeviceState {
    INVALID,
    SUSPENDED,
    ACTIVE
};

class DmDevice {
  public:
    // Returns the name of device mapper device represented by the object.
    const std::string& name() const;

    // Returns the current state of the underlying device mapper device.
    // One of INVALID, SUSPENDED or ACTIVE.
    DmDeviceState state() const;

    // Reads the device mapper table from underlying device and returns it
    // in a DmTable object.
    const DmTable& table() const;

    // Loads the device mapper table from parameter into the underlying
    // device mapper device and activate / resumes the device in the process.
    // Returns 'true' on success, false otherwise.
    bool LoadTable(const DmTable& table);

  private:
    // copy of device mapper table if one was loaded.
    DmTable table_;
    // Name of the device.
    std::string name_;
    // path to the device node for this device.
    std::string devpath_;
    // Current state of the device. Always starts with DmDeviceState::INVALID.
    DmDeviceState state_;
};

}  // namespace dm
}  // namespace android

#endif /* _LIBDM_DMDEVICE_H_ */

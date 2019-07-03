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

#ifndef _LIBDM_TEST_UTILS_H_
#define _LIBDM_TEST_UTILS_H_

#include <android-base/unique_fd.h>
#include <stddef.h>

#include <string>
#include <thread>

#include <libdm/dm.h>

namespace android {
namespace dm {

// Helper to ensure that device mapper devices are released.
class TempDevice {
  public:
    TempDevice(const std::string& name, const android::dm::DmTable& table)
        : dm_(DeviceMapper::Instance()), name_(name), valid_(false) {
        valid_ = dm_.CreateDevice(name, table);
    }
    TempDevice(TempDevice&& other) noexcept
        : dm_(other.dm_), name_(other.name_), valid_(other.valid_) {
        other.valid_ = false;
    }
    TempDevice(const std::string& name)
        : dm_(DeviceMapper::Instance()), name_(name), valid_(false) {
        valid_ = dm_.GetState(name) == DmDeviceState::ACTIVE;
    }
    ~TempDevice() {
        if (valid_) {
            dm_.DeleteDevice(name_);
        }
    }
    bool Destroy() {
        if (!valid_) {
            return false;
        }
        valid_ = false;
        return dm_.DeleteDevice(name_);
    }
    bool WaitForUdev() const {
        using namespace std::chrono_literals;
        auto start_time = std::chrono::steady_clock::now();
        while (true) {
            if (!access(path().c_str(), F_OK)) {
                return true;
            }
            if (errno != ENOENT) {
                return false;
            }
            std::this_thread::sleep_for(50ms);
            std::chrono::duration elapsed = std::chrono::steady_clock::now() - start_time;
            if (elapsed >= 5s) {
                return false;
            }
        }
    }
    std::string Release() {
        valid_ = false;
        return name_;
    }
    std::string path() const {
        std::string device_path;
        if (!dm_.GetDmDevicePathByName(name_, &device_path)) {
            return "";
        }
        return device_path;
    }
    const std::string& name() const { return name_; }
    bool valid() const { return valid_; }

    TempDevice(const TempDevice&) = delete;
    TempDevice& operator=(const TempDevice&) = delete;

    TempDevice& operator=(TempDevice&& other) noexcept {
        name_ = other.name_;
        valid_ = other.valid_;
        other.valid_ = false;
        return *this;
    }

  private:
    android::dm::DeviceMapper& dm_;
    std::string name_;
    bool valid_;
};

// Create a temporary in-memory file. If size is non-zero, the file will be
// created with a fixed size.
android::base::unique_fd CreateTempFile(const std::string& name, size_t size);

}  // namespace dm
}  // namespace android

#endif  // _LIBDM_TEST_UTILS_H_

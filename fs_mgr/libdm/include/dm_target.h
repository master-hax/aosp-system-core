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

#ifndef _LIBDM_DMTARGET_H_
#define _LIBDM_DMTARGET_H_

#include <inttypes.h>
#include <linux/dm-ioctl.h>
#include <stdint.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>

#include <string>

namespace android {
namespace dm {

class DmTarget {
  public:
    DmTarget(const std::string& name, uint64_t start = 0, uint64_t length = 0)
        : name_(name), v0_(0), v1_(0), v2_(0), start_(start), length_(length){};

    // Creates a DmTarget object from dm_target_version as read from kernel
    // with DM_LIST_VERSION ioctl.
    explicit DmTarget(const struct dm_target_versions* vers) : start_(0), length_(0) {
        CHECK(vers != nullptr) << "Can't create DmTarget with dm_target_versions set to nullptr";
        v0_ = vers->version[0];
        v1_ = vers->version[1];
        v2_ = vers->version[2];
        name_ = vers->name;
    }

    virtual ~DmTarget() = default;

    // Returns name of the target.
    const std::string& name() const { return name_; }

    // Returns size in number of sectors when this target is part of
    // a DmTable, return 0 otherwise.
    uint64_t size() const { return length_; }

    // Returns the logical sector number at which this target starts
    uint64_t start() const { return start_; }

    // Return string representation of the device mapper target version.
    std::string version() const {
        return std::to_string(v0_) + "." + std::to_string(v1_) + "." + std::to_string(v2_);
    }

    // Function that converts this object to a string of arguments that can
    // be passed to the kernel for adding this target in a table. Each target (e.g. verity, linear)
    // must implement this, for it to be used on a device.
    virtual std::string Serialize() const { return ""; }

  private:
    // Name of the target.
    std::string name_;
    // Target version.
    uint32_t v0_, v1_, v2_;
    // logical sector number start and total length (in terms of 512-byte sectors) represented
    // by this target within a DmTable.
    uint64_t start_, length_;
};

class DmTargetLinear : public DmTarget {
  public:
    DmTargetLinear() = delete;
    DmTargetLinear(uint64_t dev_off, uint64_t len, uint64_t start,
                   const std::string& dev_path = std::string())
        : DmTarget("linear", start, len) {
        devpath_ = dev_path;
        devoffset_ = dev_off;
    };

    std::string Serialize() const {
        return android::base::StringPrintf("linear %s %" PRIu64, devpath_.c_str(), devoffset_);
    }

    ~DmTargetLinear() = default;

  private:
    // Target device path, either set by the constructor
    std::string devpath_;

    // offset into the device indicated either by major:minor OR by devpath_
    uint64_t devoffset_;
};

}  // namespace dm
}  // namespace android

#endif /* _LIBDM_DMTARGET_H_ */

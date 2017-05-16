/*
 * Copyright (C) 2007 The Android Open Source Project
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

#ifndef _INIT_DEVICE_HANDLER_H
#define _INIT_DEVICE_HANDLER_H

#include <sys/stat.h>
#include <sys/types.h>

#include <algorithm>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <selinux/label.h>

#include "uevent.h"

class Permissions {
  public:
    Permissions(const std::string& name, mode_t perm, uid_t uid, gid_t gid);

    bool Match(const std::string& path) const;

    mode_t perm() const { return perm_; }
    uid_t uid() const { return uid_; }
    gid_t gid() const { return gid_; }

  protected:
    const std::string& name() const { return name_; }

  private:
    std::string name_;
    mode_t perm_;
    uid_t uid_;
    gid_t gid_;
    bool prefix_;
    bool wildcard_;
};

class SysfsPermissions : public Permissions {
  public:
    SysfsPermissions(const std::string& name, const std::string& attribute, mode_t perm, uid_t uid,
                     gid_t gid)
        : Permissions(name, perm, uid, gid), attribute_(attribute) {}

    bool MatchWithSubsystem(const std::string& path, const std::string& subsystem) const;
    void SetPermissions(const std::string& path) const;

  private:
    const std::string attribute_;
};

class Subsystem {
  public:
    friend class SubsystemParser;

    Subsystem() {}

    // Returns the full path for a uevent of a device that is a member of this subsystem,
    // according to the rules parsed from ueventd.rc
    std::string ParseDevPath(const Uevent& uevent) const {
        std::string devname = devname_source_ == DevnameSource::DEVNAME_UEVENT_DEVNAME
                                  ? uevent.device_name
                                  : android::base::Basename(uevent.path);

        return dir_name_ + "/" + devname;
    }

    bool operator==(const std::string& string_name) const { return name_ == string_name; }

  private:
    enum class DevnameSource {
        DEVNAME_UEVENT_DEVNAME,
        DEVNAME_UEVENT_DEVPATH,
    };

    std::string name_;
    std::string dir_name_ = "/dev";
    DevnameSource devname_source_;
};

class PlatformDeviceList {
  public:
    void Add(const std::string& path) { platform_devices_.emplace_back(path); }
    void Remove(const std::string& path) {
        auto it = std::find(platform_devices_.begin(), platform_devices_.end(), path);
        if (it != platform_devices_.end()) platform_devices_.erase(it);
    }
    bool Find(const std::string& path, std::string* out_path) const;
    auto size() const { return platform_devices_.size(); }

  private:
    std::vector<std::string> platform_devices_;
};

class DeviceHandler {
  public:
    friend class DeviceHandlerTester;

    DeviceHandler();
    DeviceHandler(std::vector<Permissions> dev_permissions,
                  std::vector<SysfsPermissions> sysfs_permissions,
                  std::vector<Subsystem> subsystems, bool is_booting);
    ~DeviceHandler(){};

    void HandleDeviceEvent(const Uevent& uevent);

    void FixupSysPermissions(const std::string& upath, const std::string& subsystem) const;

    void HandlePlatformDeviceEvent(const Uevent& uevent);
    void HandleBlockDeviceEvent(const Uevent& uevent) const;
    void HandleGenericDeviceEvent(const Uevent& uevent) const;

    std::vector<std::string> GetBlockDeviceSymlinks(const Uevent& uevent) const;
    void set_is_booting(bool value) { is_booting_ = value; }

  private:
    std::tuple<mode_t, uid_t, gid_t> GetDevicePermissions(
        const std::string& path, const std::vector<std::string>& links) const;
    void MakeDevice(const std::string& path, int block, int major, int minor,
                    const std::vector<std::string>& links) const;
    std::vector<std::string> GetCharacterDeviceSymlinks(const Uevent& uevent) const;
    void HandleDevice(const std::string& action, const std::string& devpath, int block, int major,
                      int minor, const std::vector<std::string>& links) const;

    std::vector<Permissions> dev_permissions_;
    std::vector<SysfsPermissions> sysfs_permissions_;
    std::vector<Subsystem> subsystems_;
    PlatformDeviceList platform_devices_;
    selabel_handle* sehandle_;
    bool is_booting_;
};

// Exposed for testing
void SanitizePartitionName(std::string* string);

#endif

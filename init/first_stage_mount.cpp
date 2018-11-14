/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "first_stage_mount.h"

#include <stdlib.h>
#include <sys/mount.h>
#include <unistd.h>

#include <chrono>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <fs_mgr.h>
#include <fs_mgr_avb.h>
#include <fs_mgr_dm_linear.h>
#include <fs_mgr_overlayfs.h>
#include <liblp/liblp.h>

#include "devices.h"
#include "switch_root.h"
#include "uevent.h"
#include "uevent_listener.h"
#include "util.h"

using android::base::Timer;

using namespace std::literals;

namespace android {
namespace init {

// Class Declarations
// ------------------
class FirstStageMount {
  public:
    FirstStageMount();
    virtual ~FirstStageMount() = default;

    // The factory method to create either FirstStageMountVBootV1 or FirstStageMountVBootV2
    // based on device tree configurations.
    static std::unique_ptr<FirstStageMount> Create();
    bool DoFirstStageMount();  // Mounts fstab entries read from device tree.
    bool InitDevices();

  protected:
    bool InitRequiredDevices();
    bool InitMappedDevice(const std::string& verity_device);
    bool CreateLogicalPartitions();
    bool MountPartition(fstab_rec* fstab_rec);
    bool MountPartitions();
    bool IsDmLinearEnabled();

    // Pure virtual functions.
    virtual bool GetDmVerityDevices() = 0;
    virtual bool SetUpDmVerity(fstab_rec* fstab_rec) = 0;

    bool need_dm_verity_;

    std::unique_ptr<fstab, decltype(&fs_mgr_free_fstab)> device_tree_fstab_;
    std::vector<fstab_rec*> mount_fstab_recs_;
    std::string super_partition_name_;
    std::unique_ptr<DeviceHandler> device_handler_;
    UeventListener uevent_listener_;
};

class FirstStageMountVBootV1 : public FirstStageMount {
  public:
    FirstStageMountVBootV1() = default;
    ~FirstStageMountVBootV1() override = default;

  protected:
    bool GetDmVerityDevices() override;
    bool SetUpDmVerity(fstab_rec* fstab_rec) override;
};

class FirstStageMountVBootV2 : public FirstStageMount {
  public:
    friend void SetInitAvbVersionInRecovery();

    FirstStageMountVBootV2();
    ~FirstStageMountVBootV2() override = default;

  protected:
    bool GetDmVerityDevices() override;
    bool SetUpDmVerity(fstab_rec* fstab_rec) override;
    bool InitAvbHandle();

    std::string device_tree_vbmeta_parts_;
    FsManagerAvbUniquePtr avb_handle_;
};

// Static Functions
// ----------------
static inline bool IsDtVbmetaCompatible() {
    return is_android_dt_value_expected("vbmeta/compatible", "android,vbmeta");
}

static bool IsRecoveryMode() {
    return access("/system/bin/recovery", F_OK) == 0;
}

// Class Definitions
// -----------------
FirstStageMount::FirstStageMount()
    : need_dm_verity_(false), device_tree_fstab_(fs_mgr_read_fstab_dt(), fs_mgr_free_fstab) {
    if (device_tree_fstab_) {
        // Stores device_tree_fstab_->recs[] into mount_fstab_recs_ (vector<fstab_rec*>)
        // for easier manipulation later, e.g., range-base for loop.
        for (int i = 0; i < device_tree_fstab_->num_entries; i++) {
            mount_fstab_recs_.push_back(&device_tree_fstab_->recs[i]);
        }
    } else {
        LOG(INFO) << "Failed to read fstab from device tree";
    }

    auto boot_devices = fs_mgr_get_boot_devices();
    device_handler_ = std::make_unique<DeviceHandler>(
            std::vector<Permissions>{}, std::vector<SysfsPermissions>{}, std::vector<Subsystem>{},
            std::move(boot_devices), false);

    super_partition_name_ = fs_mgr_get_super_partition_name();
}

std::unique_ptr<FirstStageMount> FirstStageMount::Create() {
    if (IsDtVbmetaCompatible()) {
        return std::make_unique<FirstStageMountVBootV2>();
    } else {
        return std::make_unique<FirstStageMountVBootV1>();
    }
}

bool FirstStageMount::DoFirstStageMount() {
    if (!IsDmLinearEnabled() && mount_fstab_recs_.empty()) {
        // Nothing to mount.
        LOG(INFO) << "First stage mount skipped (missing/incompatible/empty fstab in device tree)";
        return true;
    }

    if (!InitDevices()) return false;

    if (!CreateLogicalPartitions()) return false;

    if (!MountPartitions()) return false;

    return true;
}

bool FirstStageMount::InitDevices() {
    return GetDmVerityDevices() && InitRequiredDevices();
}

bool FirstStageMount::IsDmLinearEnabled() {
    for (auto fstab_rec : mount_fstab_recs_) {
        if (fs_mgr_is_logical(fstab_rec)) return true;
    }
    return false;
}

// Creates all block devices plus the device-mapper device if needed.
bool FirstStageMount::InitRequiredDevices() {
    if (IsDmLinearEnabled() || need_dm_verity_) {
        const std::string dm_path = "/devices/virtual/misc/device-mapper";
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
            LOG(INFO) << "device-mapper device not found in /sys, waiting for its uevent";
            Timer t;
            uevent_listener_.Poll(dm_callback, 10s);
            LOG(INFO) << "Wait for device-mapper returned after " << t;
        }
        if (!found) {
            LOG(ERROR) << "device-mapper device not found after polling timeout";
            return false;
        }
    }

    {
        Timer t;

        auto uevent_callback = [this](const Uevent& uevent) {
            // Ignores everything that is not a block device.
            if (uevent.subsystem != "block") {
                return ListenerAction::kContinue;
            }

            device_handler_->HandleUevent(uevent);

            return ListenerAction::kContinue;
        };
        uevent_listener_.set_expect_all_uevents(true);
        uevent_listener_.RegenerateUeventsForPath("/sys/block", uevent_callback);

        uevent_listener_.Poll(uevent_callback, 10s);
        uevent_listener_.set_expect_all_uevents(false);
        LOG(INFO) << "Wait for partitions returned after " << t;
    }

    return true;
}

bool FirstStageMount::CreateLogicalPartitions() {
    if (!IsDmLinearEnabled()) {
        return true;
    }

    const std::string lp_metadata_partition = "/dev/block/by-name/" + super_partition_name_;

    if (lp_metadata_partition.empty()) {
        LOG(ERROR) << "Could not locate logical partition tables in partition "
                   << super_partition_name_;
        return false;
    }

    auto metadata = android::fs_mgr::ReadCurrentMetadata(lp_metadata_partition);
    if (!metadata) {
        LOG(ERROR) << "Could not read logical partition metadata from " << lp_metadata_partition;
        return false;
    }
    return android::fs_mgr::CreateLogicalPartitions(*metadata.get());
}

// Creates "/dev/block/dm-XX" for dm-verity by running coldboot on /sys/block/dm-XX.
bool FirstStageMount::InitMappedDevice(const std::string& dm_device) {
    const std::string device_name(basename(dm_device.c_str()));
    const std::string syspath = "/sys/block/" + device_name;
    bool found = false;

    auto verity_callback = [&device_name, &dm_device, this, &found](const Uevent& uevent) {
        if (uevent.device_name == device_name) {
            LOG(VERBOSE) << "Creating device-mapper device : " << dm_device;
            device_handler_->HandleUevent(uevent);
            found = true;
            return ListenerAction::kStop;
        }
        return ListenerAction::kContinue;
    };

    uevent_listener_.RegenerateUeventsForPath(syspath, verity_callback);
    if (!found) {
        LOG(INFO) << "dm-verity device not found in /sys, waiting for its uevent";
        Timer t;
        uevent_listener_.Poll(verity_callback, 10s);
        LOG(INFO) << "wait for dm-verity device returned after " << t;
    }
    if (!found) {
        LOG(ERROR) << "dm-verity device not found after polling timeout";
        return false;
    }

    return true;
}

bool FirstStageMount::MountPartition(fstab_rec* fstab_rec) {
    if (fs_mgr_is_logical(fstab_rec)) {
        if (!fs_mgr_update_logical_partition(fstab_rec)) {
            return false;
        }
        if (!InitMappedDevice(fstab_rec->blk_device)) {
            return false;
        }
    }
    if (!SetUpDmVerity(fstab_rec)) {
        PLOG(ERROR) << "Failed to setup verity for '" << fstab_rec->mount_point << "'";
        return false;
    }
    if (fs_mgr_do_mount_one(fstab_rec)) {
        PLOG(ERROR) << "Failed to mount '" << fstab_rec->mount_point << "'";
        return false;
    }
    return true;
}

bool FirstStageMount::MountPartitions() {
    // If system is in the fstab then we're not a system-as-root device, and in
    // this case, we mount system first then pivot to it.  From that point on,
    // we are effectively identical to a system-as-root device.
    auto system_partition =
            std::find_if(mount_fstab_recs_.begin(), mount_fstab_recs_.end(),
                         [](const auto& rec) { return rec->mount_point == "/system"s; });

    if (system_partition != mount_fstab_recs_.end()) {
        if (!MountPartition(*system_partition)) {
            return false;
        }

        SwitchRoot((*system_partition)->mount_point);

        mount_fstab_recs_.erase(system_partition);
    }

    for (auto fstab_rec : mount_fstab_recs_) {
        if (!MountPartition(fstab_rec) && !fs_mgr_is_nofail(fstab_rec)) {
            return false;
        }
    }

    // heads up for instantiating required device(s) for overlayfs logic
    const auto devices = fs_mgr_overlayfs_required_devices(device_tree_fstab_.get());
    for (auto const& device : devices) {
        InitMappedDevice(device);
    }

    fs_mgr_overlayfs_mount_all(device_tree_fstab_.get());

    return true;
}

bool FirstStageMountVBootV1::GetDmVerityDevices() {
    std::string verity_loc_device;
    need_dm_verity_ = false;

    for (auto fstab_rec : mount_fstab_recs_) {
        // Don't allow verifyatboot in the first stage.
        if (fs_mgr_is_verifyatboot(fstab_rec)) {
            LOG(ERROR) << "Partitions can't be verified at boot";
            return false;
        }
        // Checks for verified partitions.
        if (fs_mgr_is_verified(fstab_rec)) {
            need_dm_verity_ = true;
        }
    }

    return true;
}

bool FirstStageMountVBootV1::SetUpDmVerity(fstab_rec* fstab_rec) {
    if (fs_mgr_is_verified(fstab_rec)) {
        int ret = fs_mgr_setup_verity(fstab_rec, false /* wait_for_verity_dev */);
        switch (ret) {
            case FS_MGR_SETUP_VERITY_SKIPPED:
            case FS_MGR_SETUP_VERITY_DISABLED:
                LOG(INFO) << "Verity disabled/skipped for '" << fstab_rec->mount_point << "'";
                return true;
            case FS_MGR_SETUP_VERITY_SUCCESS:
                // The exact block device name (fstab_rec->blk_device) is changed to
                // "/dev/block/dm-XX". Needs to create it because ueventd isn't started in init
                // first stage.
                return InitMappedDevice(fstab_rec->blk_device);
            default:
                return false;
        }
    }
    return true;  // Returns true to mount the partition.
}

// FirstStageMountVBootV2 constructor.
// Gets the vbmeta partitions from device tree.
// /{
//     firmware {
//         android {
//             vbmeta {
//                 compatible = "android,vbmeta";
//                 parts = "vbmeta,boot,system,vendor"
//             };
//         };
//     };
//  }
FirstStageMountVBootV2::FirstStageMountVBootV2() : avb_handle_(nullptr) {
    if (!read_android_dt_file("vbmeta/parts", &device_tree_vbmeta_parts_)) {
        PLOG(ERROR) << "Failed to read vbmeta/parts from device tree";
        return;
    }
}

bool FirstStageMountVBootV2::GetDmVerityDevices() {
    need_dm_verity_ = false;

    std::set<std::string> logical_partitions;

    // fstab_rec->blk_device has A/B suffix.
    for (auto fstab_rec : mount_fstab_recs_) {
        if (fs_mgr_is_avb(fstab_rec)) {
            need_dm_verity_ = true;
        }
        if (fs_mgr_is_logical(fstab_rec)) {
            // Don't try to find logical partitions via uevent regeneration.
            logical_partitions.emplace(basename(fstab_rec->blk_device));
        }
    }

    return true;
}

bool FirstStageMountVBootV2::SetUpDmVerity(fstab_rec* fstab_rec) {
    if (fs_mgr_is_avb(fstab_rec)) {
        if (!InitAvbHandle()) return false;
        SetUpAvbHashtreeResult hashtree_result =
                avb_handle_->SetUpAvbHashtree(fstab_rec, false /* wait_for_verity_dev */);
        switch (hashtree_result) {
            case SetUpAvbHashtreeResult::kDisabled:
                return true;  // Returns true to mount the partition.
            case SetUpAvbHashtreeResult::kSuccess:
                // The exact block device name (fstab_rec->blk_device) is changed to
                // "/dev/block/dm-XX". Needs to create it because ueventd isn't started in init
                // first stage.
                return InitMappedDevice(fstab_rec->blk_device);
            default:
                return false;
        }
    }
    return true;  // Returns true to mount the partition.
}

bool FirstStageMountVBootV2::InitAvbHandle() {
    if (avb_handle_) return true;  // Returns true if the handle is already initialized.

    avb_handle_ = FsManagerAvbHandle::Open();

    if (!avb_handle_) {
        PLOG(ERROR) << "Failed to open FsManagerAvbHandle";
        return false;
    }
    // Sets INIT_AVB_VERSION here for init to set ro.boot.avb_version in the second stage.
    setenv("INIT_AVB_VERSION", avb_handle_->avb_version().c_str(), 1);
    return true;
}

// Public functions
// ----------------
// Mounts partitions specified by fstab in device tree.
bool DoFirstStageMount() {
    // Skips first stage mount if we're in recovery mode.
    if (IsRecoveryMode()) {
        LOG(INFO) << "First stage mount skipped (recovery mode)";
        return true;
    }

    std::unique_ptr<FirstStageMount> handle = FirstStageMount::Create();
    if (!handle) {
        LOG(ERROR) << "Failed to create FirstStageMount";
        return false;
    }
    return handle->DoFirstStageMount();
}

void SetInitAvbVersionInRecovery() {
    if (!IsRecoveryMode()) {
        LOG(INFO) << "Skipped setting INIT_AVB_VERSION (not in recovery mode)";
        return;
    }

    if (!IsDtVbmetaCompatible()) {
        LOG(INFO) << "Skipped setting INIT_AVB_VERSION (not vbmeta compatible)";
        return;
    }

    // Initializes required devices for the subsequent FsManagerAvbHandle::Open()
    // to verify AVB metadata on all partitions in the verified chain.
    // We only set INIT_AVB_VERSION when the AVB verification succeeds, i.e., the
    // Open() function returns a valid handle.
    // We don't need to mount partitions here in recovery mode.
    FirstStageMountVBootV2 avb_first_mount;
    if (!avb_first_mount.InitDevices()) {
        LOG(ERROR) << "Failed to init devices for INIT_AVB_VERSION";
        return;
    }

    FsManagerAvbUniquePtr avb_handle = FsManagerAvbHandle::Open();
    if (!avb_handle) {
        PLOG(ERROR) << "Failed to open FsManagerAvbHandle for INIT_AVB_VERSION";
        return;
    }
    setenv("INIT_AVB_VERSION", avb_handle->avb_version().c_str(), 1);
}

}  // namespace init
}  // namespace android

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

#include "early_mount.h"

#include <stdlib.h>
#include <unistd.h>

#include <memory>
#include <set>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>

#include "devices.h"
#include "fs_mgr.h"
#include "fs_mgr_avb.h"

// Early Mount Class Declarations
// ------------------------------
class EarlyMountManager {
  public:
    EarlyMountManager();
    virtual ~EarlyMountManager() = default;

    bool StartEarlyMount();
    bool MountEarlyPartitions();

  protected:
    virtual bool GetDeviceInitPartitions(std::set<std::string>* out_partitions,
                                         bool* out_need_verity) = 0;
    virtual bool SetUpDmVerity(fstab_rec* fstab_rec, bool* out_need_create_verity_dev) = 0;

    // Device tree fstab entries.
    std::unique_ptr<fstab, decltype(&fs_mgr_free_fstab)> device_tree_fstab_;
    // Eligible early mount candidates, only allow /vendor, /odm and /system.
    std::vector<fstab_rec*> early_fstab_recs_;
};

class EarlyMountVBootV1 : public EarlyMountManager {
  public:
    EarlyMountVBootV1() = default;
    ~EarlyMountVBootV1() override = default;

  protected:
    bool GetDeviceInitPartitions(std::set<std::string>* out_partitions,
                                 bool* out_need_verity) override;
    bool SetUpDmVerity(fstab_rec* fstab_rec, bool* out_need_create_verity_dev) override;
};

class EarlyMountVBootV2 : public EarlyMountManager {
  public:
    EarlyMountVBootV2();
    ~EarlyMountVBootV2() override = default;

  protected:
    bool GetDeviceInitPartitions(std::set<std::string>* out_partitions,
                                 bool* out_need_verity) override;
    bool SetUpDmVerity(fstab_rec* fstab_rec, bool* out_need_create_verity_dev) override;

    std::string device_tree_vbmeta_parts_;
    std::string device_tree_by_name_prefix_;
    FsManagerAvbUniquePtr avb_handle_;
};

// Device Tree Parsing Functions
// -----------------------------
static inline bool is_dt_fstab_compatible() {
    return is_dt_value_expected("fstab/compatible", "android,fstab");
}

static inline bool is_dt_vbmeta_compatible() {
    return is_dt_value_expected("vbmeta/compatible", "android,vbmeta");
}

// Reads the content of device tree file into dt_value.
// Returns true if the read is success, false otherwise.
static bool read_dt_file(const std::string& file_name, std::string* dt_value) {
    if (android::base::ReadFileToString(file_name, dt_value)) {
        if (!dt_value->empty()) {
            dt_value->pop_back();  // Trims the trailing '\0' out.
            return true;
        }
    }
    return false;
}

bool is_dt_value_expected(const std::string& dt_file_suffix, const std::string& expected_value) {
    std::string dt_value;
    std::string file_name = kAndroidDtDir + dt_file_suffix;

    if (read_dt_file(file_name, &dt_value)) {
        if (dt_value == expected_value) {
            return true;
        }
    }
    return false;
}

// Early Mount Utility Functions
// -----------------------------
// Creates "/dev/block/dm-XX" for dm-verity by running coldboot on /sys/block/dm-XX.
static void device_init_verity_device(const std::string& dm_device) {
    const std::string device_name(basename(dm_device.c_str()));
    const std::string syspath = "/sys/block/" + device_name;

    device_init(syspath.c_str(), [&](uevent* uevent) -> coldboot_action_t {
        if (uevent->device_name == device_name) {
            LOG(VERBOSE) << "early_mount: creating dm-verity device : " << dm_device;
            return COLDBOOT_STOP;
        }
        return COLDBOOT_CONTINUE;
    });
    device_close();
}

// Creates devices with uevent->partition_name matching one in the in/out
// partition_names. Notes that the partition_names MUST have A/B suffix
// when A/B is used. Found partitions will then be removed from the
// partition_names for caller to check which devices are NOT created.
static void early_device_init(std::set<std::string>* partition_names) {
    if (partition_names->empty()) {
        return;
    }
    device_init(nullptr, [=](uevent* uevent) -> coldboot_action_t {
        // We need platform devices to create symlinks.
        if (uevent->subsystem == "platform") {
            return COLDBOOT_CREATE;
        }

        // Ignores everything that is not a block device.
        if (uevent->subsystem != "block") {
            return COLDBOOT_CONTINUE;
        }

        if (!uevent->partition_name.empty()) {
            // Matches partition names to create device nodes for partitions.
            // Both partition_names and uevent->partition_name have A/B suffix when A/B is used.
            auto iter = partition_names->find(uevent->partition_name);
            if (iter != partition_names->end()) {
                LOG(VERBOSE) << "early_mount: found partition: " << *iter;
                partition_names->erase(iter);
                if (partition_names->empty()) {
                    return COLDBOOT_STOP;  // Found all partitions, stop coldboot.
                } else {
                    return COLDBOOT_CREATE;  // Creates this device and continue to find others.
                }
            }
        }
        // Not found a partition or find an unneeded partition, continue to find others.
        return COLDBOOT_CONTINUE;
    });
}

// Early mounts /vendor, /odm or /system. The fstab is read from device-tree.
bool early_mount() {
    // Skips early mount if we're in recovery mode.
    if (access("/sbin/recovery", F_OK) == 0) {
        LOG(INFO) << "early_mount skipped (recovery mode)";
        return true;
    }

    // Firstly checks if device tree fstab entries are compatible.
    if (!is_dt_fstab_compatible()) {
        LOG(INFO) << "early_mount skipped (missing/incompatible fstab in device tree)";
        return true;
    }

    std::unique_ptr<EarlyMountManager> early_mount_handle(nullptr);

    if (is_dt_vbmeta_compatible()) {
        early_mount_handle = std::make_unique<EarlyMountVBootV2>();
    } else {
        early_mount_handle = std::make_unique<EarlyMountVBootV1>();
    }

    if (!early_mount_handle) {
        LOG(ERROR) << "early_mount: failed to create early mount handle";
    }

    return early_mount_handle->StartEarlyMount();
}

// Early Mount Class Definitions
// -----------------------------
EarlyMountManager::EarlyMountManager()
    : device_tree_fstab_(fs_mgr_read_fstab_dt(), fs_mgr_free_fstab) {
    if (!device_tree_fstab_) {
        LOG(ERROR) << "early_mount: failed to read fstab from device tree";
    }
    // Searches fstab records for /vendor, /odm or /system.
    for (auto mount_point : {"/vendor", "/odm", "/system"}) {
        fstab_rec* fstab_rec =
            fs_mgr_get_entry_for_mount_point(device_tree_fstab_.get(), mount_point);
        if (fstab_rec != nullptr) {
            early_fstab_recs_.push_back(fstab_rec);
        }
    }
}

bool EarlyMountManager::StartEarlyMount() {
    // Nothing to early mount.
    if (early_fstab_recs_.empty()) return true;

    bool need_verity;
    std::set<std::string> partition_names;

    // partition_names MUST have A/B suffix when A/B is used.
    if (!GetDeviceInitPartitions(&partition_names, &need_verity)) return false;

    bool success = false;
    early_device_init(&partition_names);  // Creates the devices we need.

    // early_device_init will remove found partitions from partition_names.
    // So if the partition_names is not empty here, it means some partitions
    // are not found.
    if (!partition_names.empty()) {
        LOG(ERROR) << "early_mount: partition(s) not found: "
                   << android::base::Join(partition_names, ", ");
        goto done;
    }

    if (need_verity) {
        // Creates /dev/device-mapper.
        device_init("/sys/devices/virtual/misc/device-mapper",
                    [&](uevent* uevent) -> coldboot_action_t { return COLDBOOT_STOP; });
    }

    if (MountEarlyPartitions()) success = true;

done:
    device_close();
    return success;
}

bool EarlyMountManager::MountEarlyPartitions() {
    bool need_create_verity_dev;

    for (auto fstab_rec : early_fstab_recs_) {
        if (!SetUpDmVerity(fstab_rec, &need_create_verity_dev)) {
            PLOG(ERROR) << "early_mount: failed to setup verity for '" << fstab_rec->mount_point
                        << "'";
            return false;
        }
        // The exact block device name (fstab_rec->blk_device) is changed to "/dev/block/dm-XX".
        // Needs to create it because ueventd isn't started during early mount (init first stage).
        if (need_create_verity_dev) {
            device_init_verity_device(fstab_rec->blk_device);
        }
        if (fs_mgr_do_mount_one(fstab_rec)) {
            PLOG(ERROR) << "early_mount: failed to mount '" << fstab_rec->mount_point << "'";
            return false;
        }
    }
    return true;
}

bool EarlyMountVBootV1::GetDeviceInitPartitions(std::set<std::string>* out_partitions,
                                                bool* out_need_verity) {
    *out_need_verity = false;
    std::string meta_partition;

    for (auto fstab_rec : early_fstab_recs_) {
        // Don't allow verifyatboot for early mounted partitions
        if (fs_mgr_is_verifyatboot(fstab_rec)) {
            LOG(ERROR) << "early_mount: partitions can't be verified at boot";
            return false;
        }
        // Checks for verified partitions.
        if (fs_mgr_is_verified(fstab_rec)) {
            *out_need_verity = true;
        }
        // Checks if verity metadata is on a separate partition and get partition
        // name from the end of the ->verity_loc path. Verity state is not partition
        // specific, so there must be only one additional partition that carries
        // verity state.
        if (fstab_rec->verity_loc) {
            if (!meta_partition.empty()) {
                LOG(ERROR) << "early_mount: more than one meta partition found: " << meta_partition
                           << ", " << basename(fstab_rec->verity_loc);
                return false;
            } else {
                meta_partition = basename(fstab_rec->verity_loc);
            }
        }
    }

    // Includes those early mount partitions and meta_partition (if any).
    // Notes that fstab_rec->blk_device has A/B suffix updated by fs_mgr when A/B is used.
    for (auto fstab_rec : early_fstab_recs_) {
        out_partitions->emplace(basename(fstab_rec->blk_device));
    }

    if (!meta_partition.empty()) {
        out_partitions->emplace(std::move(meta_partition));
    }

    return true;
}

bool EarlyMountVBootV1::SetUpDmVerity(fstab_rec* fstab_rec, bool* out_need_create_verity_dev) {
    *out_need_create_verity_dev = false;

    if (fs_mgr_is_verified(fstab_rec)) {
        int ret = fs_mgr_setup_verity(fstab_rec, false /* wait_for_verity_dev */);
        if (ret == FS_MGR_SETUP_VERITY_DISABLED) {
            LOG(INFO) << "early_mount: verity disabled for '" << fstab_rec->mount_point << "'";
        } else if (ret == FS_MGR_SETUP_VERITY_SUCCESS) {
            *out_need_create_verity_dev = true;
        } else {
            return false;
        }
    }
    return true;  // Returns true to mount the partition.
}

// EarlyMountVBootV2 constructor.
// Gets the vbmeta configurations from device tree.
// Specifically, the 'parts' and 'by_name_prefix' below.
// /{
//     firmware {
//         android {
//             vbmeta {
//                 compatible = "android,vbmeta";
//                 parts = "vbmeta,boot,system,vendor"
//                 by_name_prefix = "/dev/block/platform/soc.0/f9824900.sdhci/by-name/"
//             };
//         };
//     };
//  }
EarlyMountVBootV2::EarlyMountVBootV2() : avb_handle_(nullptr) {
    std::string file_name = kAndroidDtDir + "vbmeta/parts";
    if (!read_dt_file(file_name, &device_tree_vbmeta_parts_)) {
        PLOG(ERROR) << "early_mount: failed to read device tree file: " << file_name;
        return;
    }

    file_name = kAndroidDtDir + "vbmeta/by_name_prefix";
    if (!read_dt_file(file_name, &device_tree_by_name_prefix_)) {
        PLOG(ERROR) << "early_mount: failed to read device tree file: " << file_name;
        return;
    }
}

bool EarlyMountVBootV2::GetDeviceInitPartitions(std::set<std::string>* out_partitions,
                                                bool* out_need_verity) {
    *out_need_verity = false;

    // fstab_rec->blk_device has A/B suffix.
    for (auto fstab_rec : early_fstab_recs_) {
        if (fs_mgr_is_avb(fstab_rec)) {
            *out_need_verity = true;
        }
        out_partitions->emplace(basename(fstab_rec->blk_device));
    }

    // libavb verifies AVB metadata on all verified partitions at once.
    // e.g., The device_tree_vbmeta_parts_ will be "vbmeta,boot,system,vendor"
    // for libavb to verify metadata, even if there is only /vendor in the
    // above early_fstab_recs_.
    if (*out_need_verity) {
        if (device_tree_vbmeta_parts_.empty()) {
            LOG(ERROR) << "early_mount: missing vbmeta parts in device tree";
            return false;
        }
        std::vector<std::string> partitions = android::base::Split(device_tree_vbmeta_parts_, ",");
        std::string ab_suffix = fs_mgr_get_slot_suffix();
        for (const auto& partition : partitions) {
            // out_partitions is of type std::set so it's not an issue to emplace
            // a partition twice. e.g., /vendor might be in both places:
            //   - device_tree_vbmeta_parts_ = "vbmeta,boot,system,vendor"
            //   - early_fstab_recs_: /vendor_a
            out_partitions->emplace(partition + ab_suffix);
        }
    }
    return true;
}

bool EarlyMountVBootV2::SetUpDmVerity(fstab_rec* fstab_rec, bool* out_need_create_verity_dev) {
    if (!avb_handle_) {
        avb_handle_ = FsManagerAvbHandle::Open(device_tree_by_name_prefix_);
        if (!avb_handle_) {
            PLOG(ERROR) << "early_mount: failed to open FsManagerAvbHandle";
            return false;
        }
        // Sets INIT_AVB_VERSION here (init first stage) for init to set ro.boot.avb_version
        // in the second stage.
        setenv("INIT_AVB_VERSION", avb_handle_->avb_version().c_str(), 1);
    }

    *out_need_create_verity_dev = false;

    if (fs_mgr_is_avb(fstab_rec)) {
        if (avb_handle_->hashtree_disabled()) {
            LOG(INFO) << "avb hashtree disabled for '" << fstab_rec->mount_point << "'";
        } else if (avb_handle_->SetUpAvb(fstab_rec, false /* wait_for_verity_dev */)) {
            *out_need_create_verity_dev = true;
        } else {
            return false;
        }
    }
    return true;  // Returns true to mount the partition.
}

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

#include "init_first_stage.h"

#include <fcntl.h>
#include <paths.h>
#include <seccomp_policy.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
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
#include <cutils/android_filesystem_config.h>
#include <selinux/android.h>

#include "devices.h"
#include "fs_mgr.h"
#include "fs_mgr_avb.h"
#include "fs_mgr_dm_linear.h"
#include "log.h"
#include "selinux.h"
#include "uevent.h"
#include "uevent_listener.h"
#include "util.h"

using android::base::Timer;
using android::fs_mgr::LogicalPartitionTable;

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
    ListenerAction HandleBlockDevice(const std::string& name, const Uevent&);
    bool InitRequiredDevices();
    bool InitMappedDevice(const std::string& verity_device);
    bool CreateLogicalPartitions();
    bool MountPartitions();
    bool GetBackingDmLinearDevices();

    virtual ListenerAction UeventCallback(const Uevent& uevent);

    // Pure virtual functions.
    virtual bool GetDmVerityDevices() = 0;
    virtual bool SetUpDmVerity(fstab_rec* fstab_rec) = 0;

    bool need_dm_verity_;

    std::unique_ptr<fstab, decltype(&fs_mgr_free_fstab)> device_tree_fstab_;
    std::unique_ptr<LogicalPartitionTable> dm_linear_table_;
    std::vector<fstab_rec*> mount_fstab_recs_;
    std::set<std::string> required_devices_partition_names_;
    DeviceHandler device_handler_;
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

static void SetInitAvbVersionInRecovery();

class FirstStageMountVBootV2 : public FirstStageMount {
  public:
    friend void SetInitAvbVersionInRecovery();

    FirstStageMountVBootV2();
    ~FirstStageMountVBootV2() override = default;

  protected:
    ListenerAction UeventCallback(const Uevent& uevent) override;
    bool GetDmVerityDevices() override;
    bool SetUpDmVerity(fstab_rec* fstab_rec) override;
    bool InitAvbHandle();

    std::string device_tree_vbmeta_parts_;
    FsManagerAvbUniquePtr avb_handle_;
    ByNameSymlinkMap by_name_symlink_map_;
};

// Static Functions
// ----------------
static inline bool IsDtVbmetaCompatible() {
    return is_android_dt_value_expected("vbmeta/compatible", "android,vbmeta");
}

static bool inline IsRecoveryMode() {
    return access("/sbin/recovery", F_OK) == 0;
}

static inline bool IsDmLinearEnabled() {
    bool enabled = false;
    import_kernel_cmdline(
        false, [&enabled](const std::string& key, const std::string& value, bool in_qemu) {
            if (key == "androidboot.lrap" && value == "1") {
                enabled = true;
            }
        });
    return enabled;
}

static void SetInitAvbVersionInRecovery() {
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

    FsManagerAvbUniquePtr avb_handle =
        FsManagerAvbHandle::Open(std::move(avb_first_mount.by_name_symlink_map_));
    if (!avb_handle) {
        PLOG(ERROR) << "Failed to open FsManagerAvbHandle for INIT_AVB_VERSION";
        return;
    }
    setenv("INIT_AVB_VERSION", avb_handle->avb_version().c_str(), 1);
}

static void global_seccomp() {
    import_kernel_cmdline(false, [](const std::string& key, const std::string& value, bool in_qemu) {
        if (key == "androidboot.seccomp" && value == "global" && !set_global_seccomp_filter()) {
            LOG(FATAL) << "Failed to globally enable seccomp!";
        }
    });
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

    if (IsDmLinearEnabled()) {
        dm_linear_table_ = android::fs_mgr::LoadPartitionsFromDeviceTree();
    }
}

std::unique_ptr<FirstStageMount> FirstStageMount::Create() {
    if (IsDtVbmetaCompatible()) {
        return std::make_unique<FirstStageMountVBootV2>();
    } else {
        return std::make_unique<FirstStageMountVBootV1>();
    }
}

bool FirstStageMount::DoFirstStageMount() {
    if (!dm_linear_table_ && mount_fstab_recs_.empty()) {
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
    return GetBackingDmLinearDevices() && GetDmVerityDevices() && InitRequiredDevices();
}

bool FirstStageMount::GetBackingDmLinearDevices() {
    // Add any additional devices required for dm-linear mappings.
    if (!dm_linear_table_) {
        return true;
    }

    for (const auto& partition : dm_linear_table_->partitions) {
        for (const auto& extent : partition.extents) {
            const std::string& partition_name = android::base::Basename(extent.block_device());
            required_devices_partition_names_.emplace(partition_name);
        }
    }
    return true;
}

// Creates devices with uevent->partition_name matching one in the member variable
// required_devices_partition_names_. Found partitions will then be removed from it
// for the subsequent member function to check which devices are NOT created.
bool FirstStageMount::InitRequiredDevices() {
    if (required_devices_partition_names_.empty()) {
        return true;
    }

    if (dm_linear_table_ || need_dm_verity_) {
        const std::string dm_path = "/devices/virtual/misc/device-mapper";
        bool found = false;
        auto dm_callback = [this, &dm_path, &found](const Uevent& uevent) {
            if (uevent.path == dm_path) {
                device_handler_.HandleDeviceEvent(uevent);
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

    auto uevent_callback = [this](const Uevent& uevent) { return UeventCallback(uevent); };
    uevent_listener_.RegenerateUevents(uevent_callback);

    // UeventCallback() will remove found partitions from required_devices_partition_names_.
    // So if it isn't empty here, it means some partitions are not found.
    if (!required_devices_partition_names_.empty()) {
        LOG(INFO) << __PRETTY_FUNCTION__
                  << ": partition(s) not found in /sys, waiting for their uevent(s): "
                  << android::base::Join(required_devices_partition_names_, ", ");
        Timer t;
        uevent_listener_.Poll(uevent_callback, 10s);
        LOG(INFO) << "Wait for partitions returned after " << t;
    }

    if (!required_devices_partition_names_.empty()) {
        LOG(ERROR) << __PRETTY_FUNCTION__ << ": partition(s) not found after polling timeout: "
                   << android::base::Join(required_devices_partition_names_, ", ");
        return false;
    }

    return true;
}

bool FirstStageMount::CreateLogicalPartitions() {
    if (!dm_linear_table_) {
        return true;
    }
    return android::fs_mgr::CreateLogicalPartitions(*dm_linear_table_.get());
}

ListenerAction FirstStageMount::HandleBlockDevice(const std::string& name, const Uevent& uevent) {
    // Matches partition name to create device nodes.
    // Both required_devices_partition_names_ and uevent->partition_name have A/B
    // suffix when A/B is used.
    auto iter = required_devices_partition_names_.find(name);
    if (iter != required_devices_partition_names_.end()) {
        LOG(VERBOSE) << __PRETTY_FUNCTION__ << ": found partition: " << *iter;
        required_devices_partition_names_.erase(iter);
        device_handler_.HandleDeviceEvent(uevent);
        if (required_devices_partition_names_.empty()) {
            return ListenerAction::kStop;
        } else {
            return ListenerAction::kContinue;
        }
    }
    return ListenerAction::kContinue;
}

ListenerAction FirstStageMount::UeventCallback(const Uevent& uevent) {
    // Ignores everything that is not a block device.
    if (uevent.subsystem != "block") {
        return ListenerAction::kContinue;
    }

    if (!uevent.partition_name.empty()) {
        return HandleBlockDevice(uevent.partition_name, uevent);
    } else {
        size_t base_idx = uevent.path.rfind('/');
        if (base_idx != std::string::npos) {
            return HandleBlockDevice(uevent.path.substr(base_idx + 1), uevent);
        }
    }
    // Not found a partition or find an unneeded partition, continue to find others.
    return ListenerAction::kContinue;
}

// Creates "/dev/block/dm-XX" for dm-verity by running coldboot on /sys/block/dm-XX.
bool FirstStageMount::InitMappedDevice(const std::string& dm_device) {
    const std::string device_name(basename(dm_device.c_str()));
    const std::string syspath = "/sys/block/" + device_name;
    bool found = false;

    auto verity_callback = [&device_name, &dm_device, this, &found](const Uevent& uevent) {
        if (uevent.device_name == device_name) {
            LOG(VERBOSE) << "Creating device-mapper device : " << dm_device;
            device_handler_.HandleDeviceEvent(uevent);
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

bool FirstStageMount::MountPartitions() {
    for (auto fstab_rec : mount_fstab_recs_) {
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
    }
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
        // Checks if verity metadata is on a separate partition. Note that it is
        // not partition specific, so there must be only one additional partition
        // that carries verity state.
        if (fstab_rec->verity_loc) {
            if (verity_loc_device.empty()) {
                verity_loc_device = fstab_rec->verity_loc;
            } else if (verity_loc_device != fstab_rec->verity_loc) {
                LOG(ERROR) << "More than one verity_loc found: " << verity_loc_device << ", "
                           << fstab_rec->verity_loc;
                return false;
            }
        }
    }

    // Includes the partition names of fstab records and verity_loc_device (if any).
    // Notes that fstab_rec->blk_device has A/B suffix updated by fs_mgr when A/B is used.
    for (auto fstab_rec : mount_fstab_recs_) {
        required_devices_partition_names_.emplace(basename(fstab_rec->blk_device));
    }

    if (!verity_loc_device.empty()) {
        required_devices_partition_names_.emplace(basename(verity_loc_device.c_str()));
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

    // fstab_rec->blk_device has A/B suffix.
    for (auto fstab_rec : mount_fstab_recs_) {
        if (fs_mgr_is_avb(fstab_rec)) {
            need_dm_verity_ = true;
        }
        required_devices_partition_names_.emplace(basename(fstab_rec->blk_device));
    }

    // libavb verifies AVB metadata on all verified partitions at once.
    // e.g., The device_tree_vbmeta_parts_ will be "vbmeta,boot,system,vendor"
    // for libavb to verify metadata, even if there is only /vendor in the
    // above mount_fstab_recs_.
    if (need_dm_verity_) {
        if (device_tree_vbmeta_parts_.empty()) {
            LOG(ERROR) << "Missing vbmeta parts in device tree";
            return false;
        }
        std::vector<std::string> partitions = android::base::Split(device_tree_vbmeta_parts_, ",");
        std::string ab_suffix = fs_mgr_get_slot_suffix();
        for (const auto& partition : partitions) {
            // required_devices_partition_names_ is of type std::set so it's not an issue
            // to emplace a partition twice. e.g., /vendor might be in both places:
            //   - device_tree_vbmeta_parts_ = "vbmeta,boot,system,vendor"
            //   - mount_fstab_recs_: /vendor_a
            required_devices_partition_names_.emplace(partition + ab_suffix);
        }
    }
    return true;
}

ListenerAction FirstStageMountVBootV2::UeventCallback(const Uevent& uevent) {
    // Check if this uevent corresponds to one of the required partitions and store its symlinks if
    // so, in order to create FsManagerAvbHandle later.
    // Note that the parent callback removes partitions from the list of required partitions
    // as it finds them, so this must happen first.
    if (!uevent.partition_name.empty() &&
        required_devices_partition_names_.find(uevent.partition_name) !=
            required_devices_partition_names_.end()) {
        // GetBlockDeviceSymlinks() will return three symlinks at most, depending on
        // the content of uevent. by-name symlink will be at [0] if uevent->partition_name
        // is not empty. e.g.,
        //   - /dev/block/platform/soc.0/f9824900.sdhci/by-name/modem
        //   - /dev/block/platform/soc.0/f9824900.sdhci/by-num/p1
        //   - /dev/block/platform/soc.0/f9824900.sdhci/mmcblk0p1
        std::vector<std::string> links = device_handler_.GetBlockDeviceSymlinks(uevent);
        if (!links.empty()) {
            auto[it, inserted] = by_name_symlink_map_.emplace(uevent.partition_name, links[0]);
            if (!inserted) {
                LOG(ERROR) << "Partition '" << uevent.partition_name
                           << "' already existed in the by-name symlink map with a value of '"
                           << it->second << "', new value '" << links[0] << "' will be ignored.";
            }
        }
    }

    return FirstStageMount::UeventCallback(uevent);
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

    if (by_name_symlink_map_.empty()) {
        LOG(ERROR) << "by_name_symlink_map_ is empty";
        return false;
    }

    avb_handle_ = FsManagerAvbHandle::Open(std::move(by_name_symlink_map_));
    by_name_symlink_map_.clear();  // Removes all elements after the above std::move().

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
// First stage init entry
void first_stage_main(int argc, char** argv) {
    boot_clock::time_point start_time = boot_clock::now();

    // Clear the umask.
    umask(0);

    clearenv();
    setenv("PATH", _PATH_DEFPATH, 1);
    // Get the basic filesystem setup we need put together in the initramdisk
    // on / and then we'll let the rc file figure out the rest.
    mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755");
    mkdir("/dev/pts", 0755);
    mkdir("/dev/socket", 0755);
    mount("devpts", "/dev/pts", "devpts", 0, NULL);
#define MAKE_STR(x) __STRING(x)
    mount("proc", "/proc", "proc", 0, "hidepid=2,gid=" MAKE_STR(AID_READPROC));
    // Don't expose the raw commandline to unprivileged processes.
    chmod("/proc/cmdline", 0440);
    gid_t groups[] = {AID_READPROC};
    setgroups(arraysize(groups), groups);
    mount("sysfs", "/sys", "sysfs", 0, NULL);
    mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", 0, NULL);

    mknod("/dev/kmsg", S_IFCHR | 0600, makedev(1, 11));

    if constexpr (WORLD_WRITABLE_KMSG) {
        mknod("/dev/kmsg_debug", S_IFCHR | 0622, makedev(1, 11));
    }

    mknod("/dev/random", S_IFCHR | 0666, makedev(1, 8));
    mknod("/dev/urandom", S_IFCHR | 0666, makedev(1, 9));

    // Mount staging areas for devices managed by vold
    // See storage config details at http://source.android.com/devices/storage/
    mount("tmpfs", "/mnt", "tmpfs", MS_NOEXEC | MS_NOSUID | MS_NODEV, "mode=0755,uid=0,gid=1000");
    // /mnt/vendor is used to mount vendor-specific partitions that can not be
    // part of the vendor partition, e.g. because they are mounted read-write.
    mkdir("/mnt/vendor", 0755);

    // Now that tmpfs is mounted on /dev and we have /dev/kmsg, we can actually
    // talk to the outside world...
    InitKernelLogging(argv);

    LOG(INFO) << "init first stage started!";

    // Skips first stage mount if we're in recovery mode.
    if (!IsRecoveryMode()) {
        std::unique_ptr<FirstStageMount> handle = FirstStageMount::Create();
        if (!handle || !handle->DoFirstStageMount()) {
            LOG(FATAL) << "Failed to mount required partitions in first stage...";
        }
    } else {
        LOG(INFO) << "First stage mount skipped (recovery mode)";
    }

    SetInitAvbVersionInRecovery();

    // Enable seccomp if global boot option was passed (otherwise it is enabled in zygote).
    global_seccomp();

    // Set up SELinux, loading the SELinux policy.
    SelinuxSetupKernelLogging();
    SelinuxInitialize();

    // We're in the kernel domain, so re-exec init to transition to the init domain now
    // that the SELinux policy has been loaded.
    if (selinux_android_restorecon("/init", 0) == -1) {
        PLOG(FATAL) << "restorecon failed of /init failed";
    }

    setenv("INIT_SECOND_STAGE", "true", 1);

    static constexpr uint32_t kNanosecondsPerMillisecond = 1e6;
    uint64_t start_ms = start_time.time_since_epoch().count() / kNanosecondsPerMillisecond;
    setenv("INIT_STARTED_AT", std::to_string(start_ms).c_str(), 1);

    char* path = argv[0];
    char* args[] = {path, nullptr};
    execv(path, args);

    // execv() only returns if an error happened, in which case we
    // panic and never fall through this conditional.
    PLOG(FATAL) << "execv(\"" << path << "\") failed";
}

}  // namespace init
}  // namespace android

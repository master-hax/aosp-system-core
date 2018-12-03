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

#include "fs_mgr_roots.h"

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>

#include <android-base/logging.h>

#include "fs_mgr.h"
#include "fs_mgr_dm_linear.h"

static constexpr const char* SYSTEM_ROOT = "/system";

static bool did_map_logical_partitions = false;

struct fstab_rec* fs_mgr_fstab_rec_for_path(struct fstab* fstab, const char* path) {
    if (path == nullptr || path[0] == '\0') return nullptr;
    std::string str(path);
    while (true) {
        struct fstab_rec* result = fs_mgr_get_entry_for_mount_point(fstab, str);
        if (result != nullptr || str == "/") {
            return result;
        }
        size_t slash = str.find_last_of('/');
        if (slash == std::string::npos) return nullptr;
        if (slash == 0) {
            str = "/";
        } else {
            str = str.substr(0, slash);
        }
    }
    return nullptr;
}

int fs_mgr_fstab_ensure_path_mounted_at(struct fstab* fstab, const char* path,
                                        const char* mount_point) {
    struct fstab_rec* v = fs_mgr_fstab_rec_for_path(fstab, path);
    if (v == nullptr) {
        LOG(ERROR) << "unknown volume for path [" << path << "]";
        return -1;
    }
    if (strcmp(v->fs_type, "ramdisk") == 0) {
        // The ramdisk is always mounted.
        return 0;
    }

    if (!mount_point) {
        mount_point = v->mount_point;
    }

    // If we can't acquire the block device for a logical partition, it likely
    // was never created. In that case we try to create it.
    if (fs_mgr_is_logical(v) && !fs_mgr_update_logical_partition(v)) {
        if (did_map_logical_partitions) {
            LOG(ERROR) << "Failed to find block device for partition";
            return -1;
        }
        std::string super_name = fs_mgr_get_super_partition_name();
        if (!android::fs_mgr::CreateLogicalPartitions(super_name)) {
            LOG(ERROR) << "Failed to create logical partitions";
            return -1;
        }
        did_map_logical_partitions = true;
        if (!fs_mgr_update_logical_partition(v)) {
            LOG(ERROR) << "Failed to find block device for partition";
            return -1;
        }
    }

    std::unique_ptr<struct fstab, decltype(&fs_mgr_free_fstab)> mounted_fstab(
            fs_mgr_read_fstab("/proc/mounts"), fs_mgr_free_fstab);
    if (!mounted_fstab) {
        LOG(ERROR) << "Failed to scan mounted volumes";
        return -1;
    }

    struct fstab_rec* mv = fs_mgr_get_entry_for_mount_point(mounted_fstab.get(), v->mount_point);
    if (mv != nullptr) {
        // Volume is already mounted.
        return 0;
    }

    mkdir(mount_point, 0755);  // in case it doesn't already exist

    if (strcmp(v->fs_type, "ext4") == 0 || strcmp(v->fs_type, "squashfs") == 0 ||
        strcmp(v->fs_type, "vfat") == 0 || strcmp(v->fs_type, "f2fs") == 0) {
        int result = mount(v->blk_device, mount_point, v->fs_type, v->flags, v->fs_options);
        if (result == -1 && fs_mgr_is_formattable(v)) {
            PLOG(ERROR) << "Failed to mount " << mount_point << "; formatting";
            bool crypt_footer = fs_mgr_is_encryptable(v) && !strcmp(v->key_loc, "footer");
            if (fs_mgr_do_format(v, crypt_footer) == 0) {
                result = mount(v->blk_device, mount_point, v->fs_type, v->flags, v->fs_options);
            } else {
                PLOG(ERROR) << "Failed to format " << mount_point;
                return -1;
            }
        }

        if (result == -1) {
            PLOG(ERROR) << "Failed to mount " << mount_point;
            return -1;
        }
        return 0;
    }

    LOG(ERROR) << "unknown fs_type \"" << v->fs_type << "\" for " << mount_point;
    return -1;
}

int fs_mgr_ensure_path_mounted(const char* path) {
    // Mount at the default mount point.
    return fs_mgr_ensure_path_mounted_at(path, nullptr);
}

// Mount the volume specified by path at the given mount_point.
int fs_mgr_ensure_path_mounted_at(const char* path, const char* mount_point) {
    std::unique_ptr<struct fstab, decltype(&fs_mgr_free_fstab)> fstab(fs_mgr_read_fstab_default(),
                                                                      fs_mgr_free_fstab);

    return fs_mgr_fstab_ensure_path_mounted_at(fstab.get(), path, mount_point);
}

std::string fs_mgr_get_system_root() {
    std::unique_ptr<struct fstab, decltype(&fs_mgr_free_fstab)> fstab(fs_mgr_read_fstab_default(),
                                                                      fs_mgr_free_fstab);

    if (fs_mgr_get_entry_for_mount_point(fstab.get(), SYSTEM_ROOT) == nullptr) {
        return "/";
    } else {
        return SYSTEM_ROOT;
    }
}

bool fs_mgr_logical_partitions_mapped() {
    return did_map_logical_partitions;
}

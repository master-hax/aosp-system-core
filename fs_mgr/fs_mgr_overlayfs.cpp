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

#include <linux/fs.h>
#include <selinux/selinux.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <map>
#include <string>

#include <android-base/properties.h>
#include <android-base/strings.h>
#include <fstab/fstab.h>
#include <log/log_properties.h>

#include "fs_mgr_priv.h"
#include "fs_mgr_priv_overlayfs.h"

using namespace std::literals;

#if ALLOW_ADBD_DISABLE_VERITY == 0  // If we are a user build, provide stubs

bool fs_mgr_overlayfs_mount(const fstab*, const fstab_rec*) {
    return false;
}

#else

namespace {

bool fs_mgr_is_dir(const std::string& dir) {
    struct stat st;
    return !stat(dir.c_str(), &st) && ((st.st_mode & S_IFMT) == S_IFDIR);
}

std::string fs_mgr_get_basename(const char* mount_point) {
    auto start = strrchr(mount_point, '/');
    if (!start) return mount_point;
    if (*++start) return start;
    while ((start > mount_point) && (*--start == '/')) {
        ;
    }
    auto end = start + (*start != '/');
    while ((start > mount_point) && (*start != '/')) --start;
    if (*start == '/') ++start;
    return std::string(start, end - start);
}

// acquire the mount point's context, or make one up
std::string fs_mgr_get_context(const char* mount_point) {
    char* ctx = nullptr;
    auto len = getfilecon(mount_point, &ctx);
    if ((len > 0) && ctx) {
        std::string context(ctx, len);
        free(ctx);
        return context;
    }
    free(ctx);
    static const std::map<std::string, std::string> default_label_from_mount_point = {
            // clang-format off
            {"/system",  "system_file"},
            {"/product", "system_file"},
            {"/vendor",  "vendor_file"},
            {"/odm",     "vendor_file"},
            {"/oem",     "oemfs"},
            // clang-format on
    };
    auto it = default_label_from_mount_point.find(mount_point);
    return "u:object_r:"s +
           ((it == default_label_from_mount_point.end())
                    ? fs_mgr_get_basename(mount_point) + "_file"
                    : it->second) +
           ":s0";
}

constexpr char context_option[] = "rootcontext=";
constexpr char lowerdir_option[] = "lowerdir=";
constexpr char upperdir_option[] = "upperdir=";
constexpr char workdir_option[] = "workdir=";

bool fs_mgr_valid_overlayfs_options(const std::vector<std::string>& options) {
    static const char* flags[] = {lowerdir_option, upperdir_option, workdir_option};
    const char* dirs[sizeof(flags) / sizeof(flags[0])] = {};

    // all dir options should point to valid directories
    for (auto option : options) {
        for (size_t i = 0; i < (sizeof(flags) / sizeof(flags[0])); ++i) {
            if (android::base::StartsWith(option, flags[i])) {
                if (dirs[i]) return false;
                dirs[i] = option.c_str() + strlen(flags[i]);
                if (!fs_mgr_is_dir(dirs[i])) return false;
            }
        }
    }
    // all dir options should be specified
    for (size_t i = 0; i < (sizeof(dirs) / sizeof(dirs[0])); ++i) {
        if ((dirs[i] == nullptr) || !dirs[i][0]) return false;
    }
    return true;
}

bool fs_mgr_is_writable_dir(const std::string& dir) {
    auto test_directory = dir + "/fs_mgr_work";
    rmdir(test_directory.c_str());
    auto ret = !mkdir(test_directory.c_str(), 0777);
    return ret | !rmdir(test_directory.c_str());
}

// default options for mount_point
std::string fs_mgr_get_overlayfs_options(const char* mount_point) {
    if (!fs_mgr_is_dir(mount_point)) return "";
    const auto data_overlay = "/data/overlay/"s;
    const auto cache_overlay = "/cache/overlay/"s;
    // use data_overlay if acceptable and writable, otherwise cache_overlay
    const auto base = fs_mgr_get_basename(mount_point);
    const auto work_dir = "work/"s;
    const auto upper_dir = "upper/"s;
    auto upper = data_overlay + upper_dir + base;
    auto work = data_overlay + work_dir + base;
    const auto work_cache = cache_overlay + work_dir + base;
    if (!fs_mgr_is_dir(upper) || !fs_mgr_is_dir(work) ||
        (!fs_mgr_is_writable_dir(work) && fs_mgr_is_dir(work_cache) &&
         fs_mgr_is_writable_dir(work_cache))) {
        upper = cache_overlay + upper_dir + base;
        work = work_cache;
        if (!fs_mgr_is_dir(upper) || !fs_mgr_is_dir(work)) return "";
    }
    return "caller_credentials,"s + lowerdir_option + mount_point + "," + upperdir_option + upper +
           "," + workdir_option + work + "," + context_option + fs_mgr_get_context(mount_point);
}

// overridden options for mount_point
std::string fs_mgr_get_overlayfs_options(const fstab* fstab, const char* mount_point) {
    if (!mount_point || !mount_point[0]) return "";

    static signed char system_root = -1;  // cache for ro and constant property
    if (system_root == -1) {
        system_root = android::base::GetProperty("ro.build.system_root_image", "") == "true";
    }
    if (system_root && ("/"s == mount_point)) mount_point = "/system";

    if (!fstab) return fs_mgr_get_overlayfs_options(mount_point);

    // See if there is an override
    const auto lowerdir = "lowerdir="s + mount_point;
    const char* found = nullptr;
    for (auto i = 0; i < fstab->num_entries; i++) {
        const auto fsrec = &fstab->recs[i];
        const auto fs_options = fsrec->fs_options;
        if (!fs_options) continue;
        if (!(fsrec->fs_mgr_flags & MF_WAIT)) continue;
        if (!android::base::StartsWith(fsrec->fs_type, "overlay")) continue;
        auto options = android::base::Split(fs_options, ",");
        const char* found = nullptr;
        for (auto opt : options) {
            if (opt == lowerdir) {
                if (fs_mgr_valid_overlayfs_options(options)) {
                    found = fs_options;
                    break;
                }
            }
        }
        if (found) break;
    }
    if (!found) return fs_mgr_get_overlayfs_options(mount_point);
    return found;
}

// return true if system supports overlayfs
bool fs_mgr_wants_overlayfs() {
    if (!__android_log_is_debuggable()) return false;

    // Overlayfs available in the kernel, and patched for caller_credentials?
    static signed char overlayfs_in_kernel = -1;  // cache for constant condition
    if (overlayfs_in_kernel == -1) {
        overlayfs_in_kernel = !access("/sys/module/overlay/parameters/caller_credentials", F_OK);
    }
    return overlayfs_in_kernel;
}

// not protected for multiple threads
std::map<std::string, int> fs_mgr_verity_mode;

void fs_mgr_verity_update(fstab_rec*, const char* mount_point, int mode, int) {
    fs_mgr_verity_mode.emplace(mount_point, mode);
}

bool fs_mgr_wants_overlayfs(const fstab_rec* fsrec) {
    if (!fsrec) return false;

    // Don't check entries that are managed by vold.
    if (fsrec->fs_mgr_flags & (MF_VOLDMANAGED | MF_RECOVERYONLY)) return false;

    // Only concerned with readonly partitions.
    if (!(fsrec->flags & MS_RDONLY)) return false;

    // readonly filesystem, can not be mount -o remount,rw with any luck.
    // if free space is (near) zero.
    struct statvfs vst;
    if (("squashfs"s != fsrec->fs_type) &&
        (statvfs(fsrec->mount_point, &vst) || (vst.f_bfree >= (vst.f_blocks / 100)))) {
        return false;
    }

    // Verity enabled? (not thread safe)
    fs_mgr_verity_mode.clear();
    fs_mgr_update_verity_state(fs_mgr_verity_update);
    auto it = fs_mgr_verity_mode.find(fs_mgr_get_basename(fsrec->mount_point));
    auto found = it != fs_mgr_verity_mode.end();
    fs_mgr_verity_mode.clear();
    if (found) return false;

    return fs_mgr_wants_overlayfs();
}

}  // namespace

bool fs_mgr_overlayfs_mount(const fstab* fstab, const fstab_rec* fsrec) {
    if (!fs_mgr_wants_overlayfs(fsrec)) return false;
    auto mount_point = fsrec->mount_point;
    auto options = fs_mgr_get_overlayfs_options(fstab, mount_point);
    if (options.empty()) return false;
    auto ret = mount("overlay", mount_point, "overlay", MS_RDONLY | MS_RELATIME, options.c_str());
    if (ret) {
        PERROR << "Failed to mount overlays for " << mount_point << " opt=" << options;
        return false;
    }
    return true;
}

#endif

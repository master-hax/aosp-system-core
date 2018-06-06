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

#include <dirent.h>
#include <errno.h>
#include <linux/fs.h>
#include <selinux/selinux.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <fs_mgr_overlayfs.h>
#include <fstab/fstab.h>

#include "fs_mgr_priv.h"

using namespace std::literals;

#if ALLOW_ADBD_DISABLE_VERITY == 0  // If we are a user build, provide stubs

void fs_mgr_overlayfs_mount_all() {}

bool fs_mgr_overlayfs_setup(const char*, bool* change) {
    if (change) change = false;
    return false;
}

bool fs_mgr_overlayfs_teardown(const char*, bool* change) {
    if (change) change = false;
    return false;
}

#else  // ALLOW_ADBD_DISABLE_VERITY == 0

namespace {

// list of acceptable overlayfs backing storage
const char* overlay_mount_point[] = {"/data", "/cache"};

bool fs_mgr_is_dir(const std::string& path) {
    struct stat st;
    return !stat(path.c_str(), &st) && S_ISDIR(st.st_mode);
}

bool fs_mgr_dir_has_content(const std::string& path) {
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(path.c_str()), closedir);
    if (!dir) return false;
    dirent* entry;
    while ((entry = readdir(dir.get()))) {
        if (("."s != entry->d_name) && (".."s != entry->d_name)) return true;
    }
    return false;
}

// Similar test as overlayfs workdir= validation in the kernel for read-write
// validation, except we use fs_mgr_work.  Covers space and storage issues.
bool fs_mgr_dir_is_writable(const std::string& path) {
    auto test_directory = path + "/fs_mgr_work";
    rmdir(test_directory.c_str());
    auto ret = !mkdir(test_directory.c_str(), 0700);
    return ret | !rmdir(test_directory.c_str());
}

std::string fs_mgr_get_context(const std::string& mount_point) {
    char* ctx = nullptr;
    auto len = getfilecon(mount_point.c_str(), &ctx);
    if ((len > 0) && ctx) {
        std::string context(ctx, len);
        free(ctx);
        return context;
    }
    return "";
}

bool fs_mgr_overlayfs_enabled(const struct fstab_rec* fsrec) {
    // readonly filesystem, can not be mount -o remount,rw
    // with any luck.
    return "squashfs"s == fsrec->fs_type;
}

size_t fs_mgr_free_space(const std::string& path) {
    struct statvfs vst;
    if (statvfs(path.c_str(), &vst)) return 0;
    return vst.f_bsize / DEV_BSIZE * vst.f_bfree;
}

constexpr char upper_name[] = "upper";
constexpr char work_name[] = "work";

// Stick with _one_ active candidate, if non are active, select largest
// read-writable candidate.  Return empty string to indicate none found.
std::string fs_mgr_get_overlayfs_candidate(const std::string& mount_point) {
    if (!fs_mgr_is_dir(mount_point)) return "";
    const auto base = android::base::Basename(mount_point) + "/";
    // 1) list of r/w candidates
    std::vector<std::string> rw;
    // 2) list of override content (priority, stick to this _one_)
    std::vector<std::string> active;
    for (size_t i = 0; i < arraysize(overlay_mount_point); ++i) {
        auto dir = std::string(overlay_mount_point[i]) + "/overlay/" + base;
        auto upper = dir + upper_name;
        if (!fs_mgr_is_dir(upper)) continue;
        if (fs_mgr_dir_has_content(upper)) {
            active.push_back(dir);
        }
        auto work = dir + work_name;
        if (!fs_mgr_is_dir(work)) continue;
        if (fs_mgr_dir_is_writable(work)) {
            rw.emplace_back(std::move(dir));
        }
    }
    if (active.size() > 1) {  // ToDo: Repair the situation?
        LOG(ERROR) << "multiple active overlayfs:" << android::base::Join(active, ',');
        return "";
    }
    if (!active.empty()) {
        if (std::find(rw.begin(), rw.end(), active[0]) == rw.end()) {
            auto writable = android::base::Join(rw, ',');
            if (!writable.empty()) {
                writable = " when alternate writable backing is available:"s + writable;
            }
            LOG(WARNING) << "active overlayfs read-only" << writable;
        }
        return active[0];
    }
    if (rw.empty()) return "";

    // select one with largest free space
    auto it = std::max_element(rw.begin(), rw.end(), [](const std::string& l, const std::string& r) {
        return fs_mgr_free_space(l) > fs_mgr_free_space(r);
    });
    return *it;
}

constexpr char lowerdir_option[] = "lowerdir=";

// default options for mount_point, returns empty string for none available.
std::string fs_mgr_get_overlayfs_options(const char* mount_point) {
    auto fsrec_mount_point = std::string(mount_point);
    auto candidate = fs_mgr_get_overlayfs_candidate(fsrec_mount_point);
    if (candidate.empty()) return "";

    auto context = fs_mgr_get_context(fsrec_mount_point);
    if (!context.empty()) context = ",rootcontext="s + context;
    return "override_creds=off,"s + lowerdir_option + fsrec_mount_point + ",upperdir=" + candidate +
           upper_name + ",workdir=" + candidate + work_name + context;
}

bool fs_mgr_system_root_image(const fstab* fstab) {
    if (!fstab) {  // can not happen?
        // This will return empty on init first_stage_mount,
        // hence why we prefer checking the fstab instead.
        return android::base::GetBoolProperty("ro.build.system_root_image", false);
    }
    for (auto i = 0; i < fstab->num_entries; i++) {
        const auto fsrec = &fstab->recs[i];
        auto fsrec_mount_point = fsrec->mount_point;
        if (!fsrec_mount_point) continue;
        if ("/system"s == fsrec_mount_point) return false;
    }
    return true;
}

std::string fs_mgr_get_overlayfs_options(const fstab* fstab, const char* mount_point) {
    if (fs_mgr_system_root_image(fstab) && ("/"s == mount_point)) mount_point = "/system";

    return fs_mgr_get_overlayfs_options(mount_point);
}

// return true if system supports overlayfs
bool fs_mgr_wants_overlayfs() {
    // This will return empty on init first_stage_mount, so speculative
    // determination, empty (unset) _or_ "1" is true which differs from the
    // official ro.debuggable policy.  ALLOW_ADBD_DISABLE_VERITY == 0 should
    // protect us from false in any case, so this is insurance.
    auto debuggable = android::base::GetProperty("ro.debuggable", "1");
    if (debuggable != "1") return false;

    // Overlayfs available in the kernel, and patched for override_creds?
    static signed char overlayfs_in_kernel = -1;  // cache for constant condition
    if (overlayfs_in_kernel == -1) {
        overlayfs_in_kernel = !access("/sys/module/overlay/parameters/override_creds", F_OK);
    }
    return overlayfs_in_kernel;
}

bool fs_mgr_wants_overlayfs(const fstab_rec* fsrec) {
    if (!fsrec) return false;

    auto fsrec_mount_point = fsrec->mount_point;
    if (!fsrec_mount_point) return false;

    if (!fsrec->fs_type) return false;

    // Don't check entries that are managed by vold.
    if (fsrec->fs_mgr_flags & (MF_VOLDMANAGED | MF_RECOVERYONLY)) return false;

    // Only concerned with readonly partitions.
    if (!(fsrec->flags & MS_RDONLY)) return false;

    if (!fs_mgr_overlayfs_enabled(fsrec)) return false;

    // Verity enabled?
    const auto basename_mount_point(android::base::Basename(fsrec_mount_point));
    auto found = false;
    fs_mgr_update_verity_state(
            [&basename_mount_point, &found](fstab_rec*, const char* mount_point, int, int) {
                if (mount_point && (basename_mount_point == mount_point)) found = true;
            });
    return !found;
}

bool fs_mgr_rm_all(const std::string& path, bool* change) {
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(path.c_str()), closedir);
    if (!dir) {
        if (errno == ENOENT) {
            return true;
        }
        PERROR << "open " << path;
        return false;
    }
    dirent* entry;
    auto ret = true;
    while ((entry = readdir(dir.get()))) {
        if (("."s == entry->d_name) || (".."s == entry->d_name)) continue;
        auto file = path + "/" + entry->d_name;
        if (entry->d_type == DT_UNKNOWN) {
            struct stat st;
            if (!lstat(file.c_str(), &st) && (st.st_mode & S_IFDIR)) entry->d_type = DT_DIR;
        }
        if (entry->d_type == DT_DIR) {
            ret &= fs_mgr_rm_all(file, change);
            if (!rmdir(file.c_str())) {
                if (change) *change = true;
            } else {
                ret = false;
                PERROR << "rmdir " << file;
            }
            continue;
        }
        if (!unlink(file.c_str())) {
            if (change) *change = true;
        } else {
            ret = false;
            PERROR << "rm " << file;
        }
    }
    return ret;
}

bool fs_mgr_overlayfs_setup(const std::string& overlay, const std::string& mount_point,
                            bool* change) {
    auto ret = true;
    auto fsrec_mount_point = overlay + android::base::Basename(mount_point) + "/";
    if (!mkdir(fsrec_mount_point.c_str(), 0755)) {
        if (change) *change = true;
    } else if (errno != EEXIST) {
        ret = false;
        PERROR << "mkdir " << fsrec_mount_point;
    }

    if (!mkdir((fsrec_mount_point + work_name).c_str(), 0755)) {
        if (change) *change = true;
    } else if (errno != EEXIST) {
        ret = false;
        PERROR << "mkdir " << fsrec_mount_point << work_name;
    }

    auto new_context = fs_mgr_get_context(mount_point);
    if (!new_context.empty() && setfscreatecon(new_context.c_str())) {
        ret = false;
        PERROR << "setfscreatecon " << new_context;
    }
    auto upper = fsrec_mount_point + upper_name;
    if (!mkdir(upper.c_str(), 0755)) {
        if (change) *change = true;
    } else if (errno != EEXIST) {
        ret = false;
        PERROR << "mkdir " << upper;
    }
    if (!new_context.empty()) setfscreatecon(nullptr);

    return ret;
}

bool fs_mgr_overlayfs_mount(const fstab* fstab, const fstab_rec* fsrec) {
    if (!fs_mgr_wants_overlayfs(fsrec)) return false;
    auto fsrec_mount_point = fsrec->mount_point;
    if (!fsrec_mount_point || !fsrec_mount_point[0]) return false;
    auto options = fs_mgr_get_overlayfs_options(fstab, fsrec_mount_point);
    if (options.empty()) return false;
    auto ret = mount("overlay", fsrec_mount_point, "overlay", MS_RDONLY | MS_RELATIME,
                     options.c_str());
    if (!ret) return true;
    PERROR << "Failed to mount overlays for " << fsrec_mount_point << " opt=" << options;
    return false;
}

bool fs_mgr_overlayfs_already_mounted(const char* mount_point) {
    if (!mount_point) return false;
    std::unique_ptr<struct fstab, decltype(&fs_mgr_free_fstab)> fstab(
            fs_mgr_read_fstab("/proc/mounts"), fs_mgr_free_fstab);
    if (!fstab) return false;
    const auto lowerdir = std::string(lowerdir_option) + mount_point;
    for (auto i = 0; i < fstab->num_entries; ++i) {
        const auto fsrec = &fstab->recs[i];
        const auto fs_type = fsrec->fs_type;
        if (!fs_type) continue;
        if (("overlay"s != fs_type) && ("overlayfs"s != fs_type)) continue;
        auto fsrec_mount_point = fsrec->mount_point;
        if (!fsrec_mount_point) continue;
        if (strcmp(fsrec_mount_point, mount_point)) continue;
        const auto fs_options = fsrec->fs_options;
        if (!fs_options) continue;
        const auto options = android::base::Split(fs_options, ",");
        for (const auto opt : options) {
            if (opt == lowerdir) {
                return true;
            }
        }
    }
    return false;
}

}  // namespace

void fs_mgr_overlayfs_mount_all() {
    if (!fs_mgr_wants_overlayfs()) return;

    std::unique_ptr<struct fstab, decltype(&fs_mgr_free_fstab)> fstab(fs_mgr_read_fstab_default(),
                                                                      fs_mgr_free_fstab);
    if (!fstab) return;

    for (auto i = 0; i < fstab->num_entries; i++) {
        const auto fsrec = &fstab->recs[i];
        auto fsrec_mount_point = fsrec->mount_point;
        if (!fsrec_mount_point) continue;
        if (fs_mgr_overlayfs_already_mounted(fsrec_mount_point)) continue;
        if (!fs_mgr_overlayfs_mount(fstab.get(), fsrec)) continue;
        // hijack __mount() report format to help triage
        LINFO << "__mount(source=overlay,target=" << fsrec_mount_point << ",type=overlay)=0";
    }
}

bool fs_mgr_overlayfs_setup(const char* mount_point, bool* change) {
    if (change) *change = false;
    auto ret = false;
    if (!fs_mgr_wants_overlayfs()) return ret;

    std::unique_ptr<struct fstab, decltype(&fs_mgr_free_fstab)> fstab(fs_mgr_read_fstab_default(),
                                                                      fs_mgr_free_fstab);
    std::vector<std::string> mounts;
    if (fstab) {
        for (auto i = 0; i < fstab->num_entries; i++) {
            const auto fsrec = &fstab->recs[i];
            auto fsrec_mount_point = fsrec->mount_point;
            if (!fsrec_mount_point) continue;
            if (mount_point && strcmp(fsrec_mount_point, mount_point)) continue;
            if (fs_mgr_is_latemount(fsrec)) continue;
            if (!fs_mgr_wants_overlayfs(fsrec)) continue;
            mounts.emplace_back(fsrec_mount_point);
        }
        if (mounts.empty()) return ret;
    }

    std::vector<const std::string> dirs;
    for (auto i = 0; i < arraysize(overlay_mount_point); ++i) {
        std::string dir(overlay_mount_point[i]);
        if (!fstab || fs_mgr_get_entry_for_mount_point(fstab.get(), dir)) {
            dirs.emplace_back(std::move(dir));
        }
    }
    if (mount_point && ("/"s == mount_point) && fs_mgr_system_root_image(fstab.get())) {
        mount_point = "/system";
    }
    for (const auto& dir : dirs) {
        auto overlay = dir + "/overlay/";
        if (!mkdir(overlay.c_str(), 0755)) {
            if (change) *change = true;
        } else if (errno != EEXIST) {
            PERROR << "mkdir " << overlay;
        }
        if (!fstab && mount_point && fs_mgr_overlayfs_setup(overlay, mount_point, change)) {
            ret = true;
        }
        for (const auto& fsrec_mount_point : mounts) {
            ret |= fs_mgr_overlayfs_setup(overlay, fsrec_mount_point, change);
        }
    }
    return ret;
}

bool fs_mgr_overlayfs_teardown(const char* mount_point, bool* change) {
    if (change) *change = false;
    if (mount_point && ("/"s == mount_point)) {
        std::unique_ptr<struct fstab, decltype(&fs_mgr_free_fstab)> fstab(
                fs_mgr_read_fstab_default(), fs_mgr_free_fstab);
        if (fs_mgr_system_root_image(fstab.get())) mount_point = "/system";
    }
    auto ret = true;
    for (size_t i = 0; i < arraysize(overlay_mount_point); ++i) {
        const auto overlay = std::string(overlay_mount_point[i]) + "/overlay";
        const auto oldpath = overlay + (mount_point ?: "");
        const auto newpath = oldpath + ".teardown";
        if (rename(oldpath.c_str(), newpath.c_str())) {
            if (change) *change = true;
        } else if (errno != ENOENT) {
            ret = false;
            PERROR << "mv " << oldpath << " " << newpath;
        }
        ret &= fs_mgr_rm_all(newpath, change);
        if (!rmdir(newpath.c_str())) {
            if (change) *change = true;
        } else if (errno != ENOENT) {
            ret = false;
            PERROR << "rmdir " << newpath;
        }
        if (mount_point) {
            if (!rmdir(overlay.c_str())) {
                if (change) *change = true;
            } else if (errno != ENOENT) {
                ret = false;
                PERROR << "rmdir " << overlay;
            }
        }
    }
    if (!fs_mgr_wants_overlayfs()) {
        if (change) *change = false;
    }
    return ret;
}

#endif  // ALLOW_ADBD_DISABLE_VERITY != 0

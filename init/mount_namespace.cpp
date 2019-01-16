/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "mount_namespace.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>

#include <sys/mount.h>

#include <string>
#include <vector>

namespace android {
namespace init {
namespace {

static constexpr const char* kLinkerMountPoint = "/system/bin/linker";
static constexpr const char* kBootstrapLinkerPath = "/system/bin/bootstrap/linker";
static constexpr const char* kRuntimeLinkerPath = "/apex/com.android.runtime/bin/linker";

static constexpr const char* kBionicLibsMountPointDir = "/system/lib/";
static constexpr const char* kBootstrapBionicLibsDir = "/system/lib/bootstrap/";
static constexpr const char* kRuntimeBionicLibsDir = "/apex/com.android.runtime/lib/bionic/";

static constexpr const char* kLinkerMountPoint64 = "/system/bin/linker64";
static constexpr const char* kBootstrapLinkerPath64 = "/system/bin/bootstrap/linker64";
static constexpr const char* kRuntimeLinkerPath64 = "/apex/com.android.runtime/bin/linker64";

static constexpr const char* kBionicLibsMountPointDir64 = "/system/lib64/";
static constexpr const char* kBootstrapBionicLibsDir64 = "/system/lib64/bootstrap/";
static constexpr const char* kRuntimeBionicLibsDir64 = "/apex/com.android.runtime/lib64/bionic/";

static const std::vector<std::string> kBionicLibFileNames = {"libc.so", "libm.so", "libdl.so"};

static bool bind_mount(const char* source, const char* mount_point, bool recursive = false) {
    unsigned long mountflags = MS_BIND;
    if (recursive) {
        mountflags |= MS_REC;
    }
    if (mount(source, mount_point, nullptr, mountflags, nullptr) == -1) {
        PLOG(ERROR) << "Could not bind-mount " << source << " to " << mount_point;
        return false;
    }
    return true;
}

static bool make_shared(const char* mount_point, bool recursive = false) {
    unsigned long mountflags = MS_SHARED;
    if (recursive) {
        mountflags |= MS_REC;
    }
    if (mount(nullptr, mount_point, nullptr, mountflags, nullptr) == -1) {
        PLOG(ERROR) << "Failed to change propagation type to shared";
        return false;
    }
    return true;
}

static bool make_private(const char* mount_point, bool recursive = false) {
    unsigned long mountflags = MS_PRIVATE;
    if (recursive) {
        mountflags |= MS_REC;
    }
    if (mount(nullptr, mount_point, nullptr, mountflags, nullptr) == -1) {
        PLOG(ERROR) << "Failed to change propagation type to private";
        return false;
    }
    return true;
}

static int open_mount_namespace() {
    int fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        PLOG(ERROR) << "Cannot open fd for current mount namespace";
    }
    return fd;
}

static std::string get_mount_namespace_id() {
    std::string ret;
    if (!android::base::Readlink("/proc/self/ns/mnt", &ret)) {
        PLOG(ERROR) << "Failed to read namespace ID";
        return "";
    }
    return ret;
}

static bool bind_mount_bionic(const char* linker_source, const char* lib_dir_source,
                              const char* linker_mount_point, const char* lib_mount_dir) {
    if (access(linker_source, F_OK) != 0) {
        PLOG(INFO) << linker_source << " does not exist. skipping mounting bionic there.";
        // This can happen for 64-bit bionic in 32-bit only device.
        // It is okay to skip mounting the 64-bit bionic.
        return true;
    }
    if (!bind_mount(linker_source, linker_mount_point)) {
        return false;
    }
    if (!make_private(linker_mount_point)) {
        return false;
    }
    for (auto libname : kBionicLibFileNames) {
        std::string mount_point = lib_mount_dir + libname;
        std::string source = lib_dir_source + libname;
        if (!bind_mount(source.c_str(), mount_point.c_str())) {
            return false;
        }
        if (!make_private(mount_point.c_str())) {
            return false;
        }
    }
    return true;
}

static bool bionic_updatable() {
    static bool result = android::base::GetBoolProperty("ro.apex.bionic_updatable", false);
    return result;
}

static android::base::unique_fd default_ns_fd;
static android::base::unique_fd pre_apexd_ns_fd;

static std::string default_ns_id;
static std::string pre_apexd_ns_id;

}  // namespace

bool setup_mount_namespaces() {
    // Set the propagation type of / as shared so that any mounting event (e.g.
    // /data) is by default visible to all processes. When private mounting is
    // needed for /foo/bar, then we will make /foo/bar as a mount point (by
    // bind-mounting by to itself) and set the propagation type of the mount
    // point to private.
    if (!make_shared("/", true /*recursive*/)) return false;

    default_ns_fd.reset(open_mount_namespace());
    default_ns_id = get_mount_namespace_id();

    if (!bind_mount("/system", "/system", true /*recursive*/)) return false;
    if (!make_private("/system")) return false;

    // When bionic is updatable via the runtime APEX, we create separate mount
    // namespaces for processes that are started before and after the APEX is
    // activated by apexd. In the namespace for pre-apexd processes, the bionic
    // from the /system partition (that we call bootstrap bionic) is
    // bind-mounted. In the namespace for post-apexd processes, the bionic from
    // the runtime APEX is bind-mounted.
    //
    // Since different files (bootstrap or runtime APEX) should be mounted to
    // the same mount point paths (e.g. /system/bin/linker, /system/lib/libc.so,
    // etc.) across the two mount namespaces, we create a private mount point at
    // /system so that a mount event for the bootstrap bionic in the mount
    // namespace for pre-apexd processes is not propagated to the other mount
    // namespace for post-apexd process, and vice versa.
    //
    // Other mount points other than /system, however, are all still shared.
    if (bionic_updatable()) {
        // Clone mount namespace and switch into it.
        if (unshare(CLONE_NEWNS) == -1) {
            PLOG(ERROR) << "Cannot create mount namespace";
            return false;
        }
        LOG(INFO) << "Using pre-apexd mount namespace";

        pre_apexd_ns_fd.reset(open_mount_namespace());
        pre_apexd_ns_id = get_mount_namespace_id();
    }

    // Bind-mount bootstrap bionic.
    if (!bind_mount_bionic(kBootstrapLinkerPath, kBootstrapBionicLibsDir, kLinkerMountPoint,
                           kBionicLibsMountPointDir))
        return false;
    if (!bind_mount_bionic(kBootstrapLinkerPath64, kBootstrapBionicLibsDir64, kLinkerMountPoint64,
                           kBionicLibsMountPointDir64))
        return false;

    LOG(INFO) << "Mount namespace setup done";
    return true;
}

bool switch_to_default_mount_namespace() {
    if (default_ns_id != get_mount_namespace_id()) {
        if (setns(default_ns_fd.get(), CLONE_NEWNS) == -1) {
            PLOG(ERROR) << "Failed to switch back to the default mount namespace.";
            return false;
        }
    }

    // Bind-mount bionic from the runtime APEX since it is now available. Note
    // that in case of bionic_updatable() == false, these mounts are over the
    // existing existing bind mounts for the bootstrap bionic, which effectively
    // becomes hidden.
    if (!bind_mount_bionic(kRuntimeLinkerPath, kRuntimeBionicLibsDir, kLinkerMountPoint,
                           kBionicLibsMountPointDir))
        return false;
    if (!bind_mount_bionic(kRuntimeLinkerPath64, kRuntimeBionicLibsDir64, kLinkerMountPoint64,
                           kBionicLibsMountPointDir64))
        return false;

    LOG(INFO) << "Switched to default mount namespace";
    return true;
}

void enter_pre_apexd_mount_namespace_if_needed() {
    if (pre_apexd_ns_id != get_mount_namespace_id() && pre_apexd_ns_fd.get() != -1 &&
        bionic_updatable()) {
        if (setns(pre_apexd_ns_fd.get(), CLONE_NEWNS) == -1) {
            PLOG(ERROR) << "Failed to switch to the pre_apexd mount namespace.";
        }
    }
}

}  // namespace init
}  // namespace android

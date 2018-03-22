/*
 * Copyright (C) 2008 The Android Open Source Project
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

#define TRACE_TAG ADB

#include "sysdeps.h"

#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <string>

#include <android-base/properties.h>

#include "adb.h"
#include "adb_io.h"
#include "adb_utils.h"
#include "fs_mgr.h"

#define E2FSCK_BIN "/system/bin/e2fsck"

// Returns the device used to mount a directory in /proc/mounts.
static std::string find_proc_mount(const char* dir) {
    std::unique_ptr<FILE, int(*)(FILE*)> fp(setmntent("/proc/mounts", "r"), endmntent);
    if (!fp) {
        return "";
    }

    mntent* e;
    while ((e = getmntent(fp.get())) != nullptr) {
        if (strcmp(dir, e->mnt_dir) == 0) {
            return e->mnt_fsname;
        }
    }
    return "";
}

// Returns the device used to mount a directory in the fstab.
static std::string find_fstab_mount(const char* dir) {
    std::unique_ptr<fstab, decltype(&fs_mgr_free_fstab)> fstab(fs_mgr_read_fstab_default(),
                                                               fs_mgr_free_fstab);
    struct fstab_rec* rec = fs_mgr_get_entry_for_mount_point(fstab.get(), dir);
    return rec ? rec->blk_device : "";
}

// The proc entry for / is full of lies, so check fstab instead.
// /proc/mounts lists rootfs and /dev/root, neither of which is what we want.
static std::string find_mount(const char* dir, bool is_root) {
    if (is_root) {
        return find_fstab_mount(dir);
    } else {
       return find_proc_mount(dir);
    }
}

bool make_block_device_writable(const std::string& dev) {
    int fd = unix_open(dev.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        return false;
    }

    int OFF = 0;
    bool result = (ioctl(fd, BLKROSET, &OFF) != -1);
    unix_close(fd);
    return result;
}

static bool is_ext2fs(int fd, const char* dir) {
    struct statfs fs;
    if (statfs(dir, &fs)) {
        return false;
    }
    return fs.f_type == EXT4_SUPER_MAGIC;
}

static bool fsck_and_remount(int fd, const std::string& dev, const char* dir) {
    if (!is_ext2fs(fd, dir)) {
        return false;
    }
    if (access(E2FSCK_BIN, X_OK)) {
        WriteFdFmt(fd, "could not find e2fsck to attempt deduplication: %s\n", strerror(errno));
        return false;
    }

    WriteFdExactly(fd, "Attempting to run e2fsck to undo deduplication.\n");

    pid_t pid = fork();
    if (pid == -1) {
        return false;
    }
    if (pid == 0) {
        // Arguments to e2fsck.
        // We need -f since the filesystem is live (mounted readonly), and
        // otherwise, e2fsck will immediately fail. We also need -p, otherwise
        // e2fsck can stop and prompt on details we don't care about (like the
        // timestamp of the superblock). We don't want to pass -y and have it
        // fix more serious issues, so we pass -p instead.
        const char* argv[] = {E2FSCK_BIN, "-f", "-p", "-E", "unshare_blocks", dev.c_str(), nullptr};
        if (execvp(E2FSCK_BIN, const_cast<char**>(argv))) {
            _exit(-1);
        }
    } else {
        int status = 0;
        int ret = TEMP_FAILURE_RETRY(waitpid(pid, &status, 0));
        if (ret < 0) {
            WriteFdFmt(fd, "could not determine the status of e2fsck: %s\n", strerror(errno));
            return false;
        }
        if (!WIFEXITED(status)) {
            WriteFdFmt(fd, "e2fsck exited abnormally with status %x\n", status);
            return false;
        }
        int rc = WEXITSTATUS(status);
        // e2fsck returns a bitstring as an exit code; bits 3 and higher indicate
        // series errors.
        if (rc >= 8) {
            WriteFdFmt(fd, "e2fsck exited with error code %d\n", rc);
            return false;
        }
    }

    // Finally, try to mount again.
    if (mount(dev.c_str(), dir, "none", MS_REMOUNT, nullptr)) {
        return false;
    }

    // We want the device to reboot before actually letting the user write
    // to the partition, so re-mount it again read-only.
    mount(dev.c_str(), dir, "none", MS_REMOUNT | MS_RDONLY, nullptr);
    return true;
}

static bool remount_partition(int fd, const char* dir, bool* reboot) {
    if (!directory_exists(dir)) {
        return true;
    }
    bool is_root = strcmp(dir, "/") == 0;
    std::string dev = find_mount(dir, is_root);
    // Even if the device for the root is not found, we still try to remount it
    // as rw. This typically only happens when running Android in a container:
    // the root will almost always be in a loop device, which is dynamic, so
    // it's not convenient to put in the fstab.
    if (dev.empty() && !is_root) {
        return true;
    }
    if (!dev.empty() && !make_block_device_writable(dev)) {
        WriteFdFmt(fd, "remount of %s failed; couldn't make block device %s writable: %s\n",
                   dir, dev.c_str(), strerror(errno));
        return false;
    }
    if (mount(dev.c_str(), dir, "none", MS_REMOUNT | MS_BIND, nullptr) == -1) {
        // This is useful for cases where the superblock is already marked as
        // read-write, but the mount itself is read-only, such as containers
        // where the remount with just MS_REMOUNT is forbidden by the kernel.
        WriteFdFmt(fd, "remount of the %s mount failed: %s.\n", dir, strerror(errno));
        return false;
    }
    int rv = mount(dev.c_str(), dir, "none", MS_REMOUNT, nullptr);
    if (!rv) {
        return true;
    }
    // If we failed to remount due to a read-only file system, then it could
    // be due to ext4 deduplication, so we try to fsck and remount.
    if (errno == EROFS) {
        if (fsck_and_remount(fd, dev, dir)) {
            *reboot |= true;
            return true;
        }
        errno = EROFS;
    }
    WriteFdFmt(fd, "remount of the %s superblock failed: %s\n", dir, strerror(errno));
    return false;
}

void remount_service(int fd, void* cookie) {
    if (getuid() != 0) {
        WriteFdExactly(fd, "Not running as root. Try \"adb root\" first.\n");
        adb_close(fd);
        return;
    }

    bool system_verified = !(android::base::GetProperty("partition.system.verified", "").empty());
    bool vendor_verified = !(android::base::GetProperty("partition.vendor.verified", "").empty());

    if (system_verified || vendor_verified) {
        // Allow remount but warn of likely bad effects
        bool both = system_verified && vendor_verified;
        WriteFdFmt(fd,
                   "dm_verity is enabled on the %s%s%s partition%s.\n",
                   system_verified ? "system" : "",
                   both ? " and " : "",
                   vendor_verified ? "vendor" : "",
                   both ? "s" : "");
        WriteFdExactly(fd,
                       "Use \"adb disable-verity\" to disable verity.\n"
                       "If you do not, remount may succeed, however, you will still "
                       "not be able to write to these volumes.\n");
    }

    bool success = true;
    bool reboot = false;
    if (android::base::GetBoolProperty("ro.build.system_root_image", false)) {
        success &= remount_partition(fd, "/", &reboot);
    } else {
        success &= remount_partition(fd, "/system", &reboot);
    }
    success &= remount_partition(fd, "/vendor", &reboot);
    success &= remount_partition(fd, "/oem", &reboot);

    if (!success) {
        WriteFdExactly(fd, "remount failed\n");
    } else if (reboot) {
        WriteFdExactly(fd, "reboot needed; please reboot and try adb remount again\n");
    } else {
        WriteFdExactly(fd, "remount succeeded\n");
    }

    adb_close(fd);
}

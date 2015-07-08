/*
 * Copyright 2011, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <unistd.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cutils/android_reboot.h>

#define UNUSED __attribute__((unused))

static int has_mount_option(const char* opts, const char* opt_to_find)
{
  int ret = 0;
  char* copy = NULL;
  char* opt;
  char* rem;

  while ((opt = strtok_r(copy ? NULL : (copy = strdup(opts)), ",", &rem))) {
      if (!strcmp(opt, opt_to_find)) {
          ret = 1;
          break;
      }
  }

  free(copy);
  return ret;
}

/* Check to see if /proc/mounts contains any writeable filesystems
 * backed by a block device.
 * Return true if none found, else return false.
 */
static int remount_ro_done(void)
{
    FILE* fp;
    struct mntent* mentry;
    int found_rw_fs = 0;

    if ((fp = setmntent("/proc/mounts", "r")) == NULL) {
        /* If we can't read /proc/mounts, just give up. */
        return 1;
    }
    while ((mentry = getmntent(fp)) != NULL) {
        if (!strncmp(mentry->mnt_fsname, "/dev/block", 10) &&
            has_mount_option(mentry->mnt_opts, "rw")) {
            found_rw_fs = 1;
            break;
        }
    }
    endmntent(fp);

    return !found_rw_fs;
}

/* Find all read+write block devices in /proc/mounts and write them to
 * |rw_entries|. Return the number of entries written.
 */
static int find_rw(struct mntent* rw_entries, int rw_entries_len)
{
    FILE* fp;
    struct mntent* mentry;
    int count = 0;

    if ((fp = setmntent("/proc/mounts", "r")) == NULL) {
        return 0;
    }
    while ((mentry = getmntent(fp)) != NULL && count < rw_entries_len) {
        if (!strncmp(mentry->mnt_fsname, "/dev/block", 10) &&
            has_mount_option(mentry->mnt_opts, "rw")) {
            rw_entries[count] = *mentry;
            rw_entries[count].mnt_fsname = strdup(mentry->mnt_fsname);
            rw_entries[count].mnt_dir = strdup(mentry->mnt_dir);
            rw_entries[count].mnt_type = strdup(mentry->mnt_type);
            rw_entries[count].mnt_opts = strdup(mentry->mnt_opts);
            ++count;
        }
    }
    endmntent(fp);
    return count;
}

static void free_rw(struct mntent* rw_entries, int rw_entries_len)
{
    int i;
    for (i = 0; i < rw_entries_len; ++i) {
        free(rw_entries[i].mnt_fsname);
        free(rw_entries[i].mnt_dir);
        free(rw_entries[i].mnt_type);
        free(rw_entries[i].mnt_opts);
    }
}

/* Remounting filesystems read-only is difficult when there are files
 * opened for writing or pending deletes on the filesystem.  There is
 * no way to force the remount with the mount(2) syscall.  The magic sysrq
 * 'u' command does an emergency remount read-only on all writable filesystems
 * that have a block device (i.e. not tmpfs filesystems) by calling
 * emergency_remount(), which knows how to force the remount to read-only.
 * Unfortunately, that is asynchronous, and just schedules the work and
 * returns.  The best way to determine if it is done is to read /proc/mounts
 * repeatedly until there are no more writable filesystems mounted on
 * block devices.
 */
static int remount_ro(void)
{
    int fd, cnt = 0;

    /* Trigger the remount of the filesystems as read-only,
     * which also marks them clean.
     */
    fd = open("/proc/sysrq-trigger", O_WRONLY);
    if (fd < 0) {
        return -1;
    }
    write(fd, "u", 1);
    close(fd);


    /* Now poll /proc/mounts till it's done */
    while (!remount_ro_done() && (cnt < 50)) {
        usleep(100000);
        cnt++;
    }

    return (cnt < 50) ? 0 : -1;
}

static void remount_ro_callback(struct mntent* rw_entries, int rw_entries_len,
                                void (*cb_on_remount)(const struct mntent*))
{
    int i;
    for (i = 0; i < rw_entries_len; ++i)
        cb_on_remount(&rw_entries[i]);
}

int android_reboot_with_callback(
    int cmd, int flags UNUSED, const char *arg,
    void (*cb_on_remount)(const struct mntent*))
{
    int ret;
    struct mntent rw_entries[16];
    int rw_entries_len = 0;

    sync();
    if (cb_on_remount) {
        rw_entries_len =
            find_rw(rw_entries, sizeof(rw_entries) / sizeof(rw_entries[0]));
    }
    ret = remount_ro();
    if (cb_on_remount) {
        if (!ret) {
            remount_ro_callback(rw_entries, rw_entries_len, cb_on_remount);
        }
        free_rw(rw_entries, rw_entries_len);
    }

    switch (cmd) {
        case ANDROID_RB_RESTART:
            ret = reboot(RB_AUTOBOOT);
            break;

        case ANDROID_RB_POWEROFF:
            ret = reboot(RB_POWER_OFF);
            break;

        case ANDROID_RB_RESTART2:
            ret = syscall(__NR_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
                           LINUX_REBOOT_CMD_RESTART2, arg);
            break;

        default:
            ret = -1;
    }

    return ret;
}

int android_reboot(int cmd, int flags, const char *arg)
{
    return android_reboot_with_callback(cmd, flags, arg, NULL);
}

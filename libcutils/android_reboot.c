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
#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cutils/android_reboot.h>
#include <cutils/list.h>

#define UNUSED __attribute__((unused))
#define READONLY_CHECK_TIMES 50

typedef struct {
    struct listnode list;
    struct mntent entry;
} mntent_list;

static bool has_mount_option(const char* opts, const char* opt_to_find)
{
  bool ret = false;
  char* copy = NULL;
  char* opt;
  char* rem;

  while ((opt = strtok_r(copy ? NULL : (copy = strdup(opts)), ",", &rem))) {
      if (!strcmp(opt, opt_to_find)) {
          ret = true;
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
static bool remount_ro_done(void)
{
    FILE* fp;
    struct mntent* mentry;
    int found_rw_fs = 0;

    if ((fp = setmntent("/proc/mounts", "r")) == NULL) {
        /* If we can't read /proc/mounts, just give up. */
        return true;
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
static void find_rw(struct listnode* rw_entries)
{
    FILE* fp;
    struct mntent* mentry;

    if ((fp = setmntent("/proc/mounts", "r")) == NULL) {
        return;
    }
    while ((mentry = getmntent(fp)) != NULL) {
        if (!strncmp(mentry->mnt_fsname, "/dev/block", 10) &&
            has_mount_option(mentry->mnt_opts, "rw")) {
            mntent_list* item = (mntent_list*)calloc(1, sizeof(mntent_list));
            item->entry = *mentry;
            item->entry.mnt_fsname = strdup(mentry->mnt_fsname);
            item->entry.mnt_dir = strdup(mentry->mnt_dir);
            item->entry.mnt_type = strdup(mentry->mnt_type);
            item->entry.mnt_opts = strdup(mentry->mnt_opts);
            list_add_tail(rw_entries, &item->list);
        }
    }
    endmntent(fp);
}

static void free_rw(struct listnode* rw_entries)
{
    struct listnode* node;
    struct listnode* n;
    list_for_each_safe(node, n, rw_entries) {
        mntent_list* item = node_to_item(node, mntent_list, list);
        free(item->entry.mnt_fsname);
        free(item->entry.mnt_dir);
        free(item->entry.mnt_type);
        free(item->entry.mnt_opts);
        free(item);
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
static bool remount_ro(void)
{
    int fd, cnt = 0;

    /* Trigger the remount of the filesystems as read-only,
     * which also marks them clean.
     */
    fd = TEMP_FAILURE_RETRY(open("/proc/sysrq-trigger", O_WRONLY));
    if (fd < 0) {
        return false;
    }
    TEMP_FAILURE_RETRY(write(fd, "u", 1));
    close(fd);


    /* Now poll /proc/mounts till it's done */
    while (!remount_ro_done() && (cnt < READONLY_CHECK_TIMES)) {
        usleep(100000);
        cnt++;
    }

    return cnt < READONLY_CHECK_TIMES;
}

static void remount_ro_callback(struct listnode* rw_entries,
                                void (*cb_on_remount)(const struct mntent*))
{
    struct listnode* node;
    list_for_each(node, rw_entries) {
        mntent_list* item = node_to_item(node, mntent_list, list);
        cb_on_remount(&item->entry);
    }
}

int android_reboot_with_callback(
    int cmd, int flags UNUSED, const char *arg,
    void (*cb_on_remount)(const struct mntent*))
{
    int ret;
    bool remounted;
    list_declare(rw_entries);

    sync();
    if (cb_on_remount) {
        find_rw(&rw_entries);
    }
    remounted = remount_ro();
    if (cb_on_remount) {
        if (remounted) {
            remount_ro_callback(&rw_entries, cb_on_remount);
        }
        free_rw(&rw_entries);
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

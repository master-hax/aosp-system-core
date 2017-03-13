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

#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cutils/android_reboot.h>
#include <cutils/klog.h>
#include <cutils/list.h>

#define TAG "android_reboot"
#define READONLY_CHECK_MS 5000
#define READONLY_CHECK_TIMES 50

typedef struct {
    struct listnode list;
    struct mntent entry;
    int is_mounted;
} mntent_list;

static bool is_block_device(const char* fsname)
{
    return !strncmp(fsname, "/dev/block", 10);
}

static bool is_emulated_device(struct mntent* mentry) {
    return !strncmp(mentry->mnt_fsname, "/data/", 6) && !strncmp(mentry->mnt_type, "sdcardfs", 8);
}

static void alloc_and_add(struct listnode* entries, struct mntent* mentry) {
    mntent_list* item = (mntent_list*)calloc(1, sizeof(mntent_list));
    item->entry = *mentry;
    item->entry.mnt_fsname = strdup(mentry->mnt_fsname);
    item->entry.mnt_dir = strdup(mentry->mnt_dir);
    item->entry.mnt_type = strdup(mentry->mnt_type);
    item->entry.mnt_opts = strdup(mentry->mnt_opts);
    item->is_mounted = 1;
    list_add_tail(entries, &item->list);
}

/* Find all read+write block devices and emulated devices in /proc/mounts
 * and add them to correpsponding list.
 */
static void find_partition_to_umount(struct listnode* entries_bdev_rw,
                                     struct listnode* entries_emulated) {
    FILE* fp;
    struct mntent* mentry;

    if ((fp = setmntent("/proc/mounts", "r")) == NULL) {
        KLOG_WARNING(TAG, "Failed to open /proc/mounts.\n");
        return;
    }
    while ((mentry = getmntent(fp)) != NULL) {
        if (is_block_device(mentry->mnt_fsname) && hasmntopt(mentry, "rw")) {
            alloc_and_add(entries_bdev_rw, mentry);
        } else if (is_emulated_device(mentry)) {
            alloc_and_add(entries_emulated, mentry);
        }
    }
    endmntent(fp);
}

static void free_entries(struct listnode* entries)
{
    struct listnode* node;
    struct listnode* n;
    list_for_each_safe(node, n, entries) {
        mntent_list* item = node_to_item(node, mntent_list, list);
        free(item->entry.mnt_fsname);
        free(item->entry.mnt_dir);
        free(item->entry.mnt_type);
        free(item->entry.mnt_opts);
        free(item);
    }
}

static bool umount_entries(struct listnode* entries, int max_retry, int flags) {
    int umount_done;
    int retry_counter = 0;
    int r;
    struct listnode* node;

    while (1) {
        umount_done = 1;
        list_for_each(node, entries) {
            mntent_list* item = node_to_item(node, mntent_list, list);
            if (item->is_mounted) {
                r = umount2(item->entry.mnt_dir, flags);
                if (r == 0) {
                    item->is_mounted = 0;
                    KLOG_INFO(TAG, "umounted %s, flags:0x%x\n", item->entry.mnt_fsname, flags);
                } else {
                    umount_done = 0;
                    KLOG_WARNING(TAG, "cannot umount %s, errno %d, flags:0x%x\n",
                                 item->entry.mnt_fsname, errno, flags);
                }
            }
        }
        if (umount_done) break;
        retry_counter++;
        if (retry_counter >= max_retry) break;
        usleep(100000);
    }
    return umount_done;
}

static void kill_all_other_processes() {
    int fd;
    int killed;

    fd = TEMP_FAILURE_RETRY(open("/proc/sysrq-trigger", O_WRONLY));
    if (fd < 0) {
        KLOG_WARNING(TAG, "Failed to open sysrq-trigger.\n");
        return;
    }
    if (TEMP_FAILURE_RETRY(write(fd, "i", 1)) != 1) {
        close(fd);
        KLOG_WARNING(TAG, "Failed to write to sysrq-trigger.\n");
        return;
    }
    close(fd);

    killed = 0;
    while (waitpid(-1, NULL, WNOHANG) > 0) killed++;
    if (killed > 0) KLOG_WARNING(TAG, "killed %d processes\n", killed);
}

/* Try umounting all emulated file systems R/W block device cfile systems.
 * This will just try umount and give it up if it fails.
 * For fs like ext4, this is ok as file system will be marked as unclean shutdown
 * and necessary check can be done at the next reboot.
 * For safer shutdown, caller of android_reboot needs to make sure that
 * all processes / emulated partition for the target fs are all cleaned-up.
 */
static void try_umount(void (*cb_on_umount)(const struct mntent*)) {
    struct listnode* node;

    list_declare(entries_emulated);
    list_declare(entries_bdev_rw);

    find_partition_to_umount(&entries_bdev_rw, &entries_emulated);
    kill_all_other_processes();
    sync();
    /* Pending writes in emulated partitions can fail umount. After a few trials, detach it so
     * that it can be umounted when all writes are done.
     */
    if (!umount_entries(&entries_emulated, 2, 0)) {
        umount_entries(&entries_emulated, 1, MNT_DETACH);
    }
    sync();
    /* data partition needs all pending writes to be completed and all emulated partitions
     * umounted. If umount failed in the above step, it DETACH is requested, so umount can
     * still happen while waiting for /data. If 5 secs waiting is not good enough, give up and
     * leave it to e2fsck after reboot to fix it.
     */
    if (!umount_entries(&entries_bdev_rw, 50, 0)) {
        /* Last resort, detach and hope it finish before shutdown. */
        umount_entries(&entries_bdev_rw, 1, MNT_DETACH);
    }
    if (cb_on_umount) {
        list_for_each(node, &entries_bdev_rw) {
            mntent_list* item = node_to_item(node, mntent_list, list);
            if (!item->is_mounted) cb_on_umount(&item->entry);
        }
    }

    free_entries(&entries_emulated);
    free_entries(&entries_bdev_rw);
}

int android_reboot_with_callback(int cmd, int flags __unused, const char* arg,
                                 void (*cb_on_umount)(const struct mntent*)) {
    int ret;

    if (cmd !=
        (int)ANDROID_RB_THERMOFF) {  // for thermal shutdown, just reboot. e2fsck will fix it.
        try_umount(cb_on_umount);
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

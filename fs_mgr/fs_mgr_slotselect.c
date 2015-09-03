/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cutils/properties.h>

#include "fs_mgr.h"
#include "fs_mgr_priv.h"

#include "bootloader.h"

static int open_misc_device(struct fstab *fstab)
{
    int n;
    for (n = 0; n < fstab->num_entries; n++) {
        if (strcmp(fstab->recs[n].mount_point, "/misc") == 0) {
            return open(fstab->recs[n].blk_device, O_RDONLY);
        }
    }
    return -1;
}

static char *get_active_slot_suffix_from_misc(struct fstab *fstab)
{
    int misc_fd;
    ssize_t num_read;
    struct bootloader_message msg;

    misc_fd = open_misc_device(fstab);
    if (misc_fd == -1)
        return NULL;

    do {
        num_read = read(misc_fd, &msg, sizeof(msg));
    } while (num_read == -1 && errno == EINTR);
    // Linux will never return partial reads when reading from block
    // devices so no need to worry about them.
    if (num_read != sizeof(msg)) {
        ERROR("Error reading bootloader_message (%s)\n", strerror(errno));
        close(misc_fd);
        return NULL;
    }
    close(misc_fd);
    if (msg.slot_suffix[0] == '\0')
        return NULL;
    return strndup(msg.slot_suffix, 32);
}

const char *get_active_slot_suffix(struct fstab *fstab)
{
    static char propbuf[PROPERTY_VALUE_MAX];
    static char *suffix = NULL;

    if (suffix != NULL)
        return suffix;

    // Get the suffix from the kernel commandline. On bootloaders
    // natively supporting A/B we'll hit this path every time so don't
    // bother logging it.
    property_get("ro.boot.slot_suffix", propbuf, "");
    if (propbuf[0] != '\0') {
        suffix = propbuf;
        return suffix;
    }

    // If we couldn't get the suffix from the kernel cmdline, try the
    // the misc partition.
    suffix = get_active_slot_suffix_from_misc(fstab);
    if (suffix != NULL) {
        INFO("Using slot suffix \"%s\" from misc\n", suffix);
        return suffix;
    }

    // If that didn't work, fall back to _a. The reasoning here is
    // that since the fstab has the slotselect option set (otherwise
    // we wouldn't end up here) we must assume that partitions are
    // indeed set up for A/B. This corner-case is important because we
    // may be on this codepath on newly provisioned A/B devices where
    // misc isn't set up properly (it's just zeroes) and the
    // bootloader does not (yet) natively support A/B.
    //
    // Why '_a'? Because that's what system/extras/boot_control_copy
    // is using and since the bootloader isn't A/B aware we assume
    // slots are set up this way.
    WARNING("Could not determine slot suffix, falling back to \"_a\".\n");
    suffix = strdup("_a");
    return suffix;
}

void fs_mgr_update_for_slotselect(struct fstab *fstab)
{
    int n;
    for (n = 0; n < fstab->num_entries; n++) {
        if (fstab->recs[n].fs_mgr_flags & MF_SLOTSELECT) {
            const char *suffix;
            suffix = get_active_slot_suffix(fstab);
            if (suffix != NULL) {
                char *tmp;
                if (asprintf(&tmp, "%s%s", fstab->recs[n].blk_device,
                             suffix) > 0) {
                    free(fstab->recs[n].blk_device);
                    fstab->recs[n].blk_device = tmp;
                } else {
                    ERROR("Error updating block device name\n");
                }
            }
        }
    }
}

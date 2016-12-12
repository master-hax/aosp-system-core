/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <libavb/libavb.h>
#include <utils/Compat.h>

#include "fs_mgr.h"
#include "fs_mgr_avb_ops.h"
#include "fs_mgr_priv.h"

/* Maximum allow length (in bytes) of a partition name, not including
 * ab_suffix.
 */
#define PART_NAME_MAX_SIZE 32

/* For unused function parameters to skip -Werror,-Wunused-parameter. */
#define UNUSED(x) (void)(x)

static struct fstab* g_fstab = NULL;

static AvbIOResult read_from_partition(AvbOps* ops, const char* partition,
                                       int64_t offset, size_t num_bytes,
                                       void* buffer, size_t* out_num_read)
{
    int fd = -1;
    int res;
    char* path;
    ssize_t num_read;
    int64_t total_size;
    struct fstab_rec* fstab_entry;
    char mount_point[PART_NAME_MAX_SIZE + 1];
    AvbIOResult ret = AVB_IO_RESULT_ERROR_IO;

    UNUSED(ops);

    /* The input partition name is without ab_suffix and we use it to
     * look up the corresponding blk_device from g_fstab*, where the
     * blk_device has the ab_suffix updated by fs_mgr_slotselect.
     */

    strlcpy(mount_point, "/", sizeof(mount_point));
    res = strlcat(mount_point, partition, sizeof(mount_point));

    if (res < 0 || (size_t)res >= sizeof(mount_point)) {
        ERROR("Error building mount_point; partition name (%s) too long?\n",
              partition);
        goto out;
    }

    fstab_entry = fs_mgr_get_entry_for_mount_point(g_fstab, mount_point);

    if (fstab_entry == NULL) {
        ERROR("Partition (%s) not found in fstab\n", partition);
        goto out;
    }

    path = fstab_entry->blk_device;
    fd = TEMP_FAILURE_RETRY(open(path, O_RDONLY | O_CLOEXEC));

    if (fd == -1) {
        ERROR("Failed to open %s (%s)\n", path, strerror(errno));
        goto out;
    }

    /* If offset is negative, interprets its absolute value as the
       number of bytes from the end of the partition. */
    if (offset < 0) {
        total_size = lseek64(fd, 0, SEEK_END);
        if (total_size == -1) {
            ERROR("Failed to lseek64 to end of the partition\n");
            goto out;
        }
        offset = total_size + offset;
        /* Repositions the offset to the beginning. */
        if (lseek64(fd, 0, SEEK_SET) == -1) {
            ERROR("Failed to lseek64 to the beginning of the partition\n");
            goto out;
        }
    }

    /* On Linux, we never get partial reads from block devices (except
     * for EOF).
     */
    num_read = TEMP_FAILURE_RETRY(pread64(fd, buffer, num_bytes, offset));

    if (num_read < 0 || (size_t)num_read != num_bytes) {
        ERROR("Failed to read %zu bytes from %s offset %" PRId64 " (%s)\n",
              num_bytes, path, offset, strerror(errno));
        goto out;
    }

    if (out_num_read != NULL) {
        *out_num_read = num_read;
    }

    ret = AVB_IO_RESULT_OK;

out:
    if (fd != -1) {
        if (close(fd) != 0) {
            ERROR("Error closing file descriptor.\n");
        }
    }

    return ret;
}

static AvbIOResult dummy_read_rollback_index(AvbOps* ops,
                                             size_t rollback_index_location,
                                             uint64_t* out_rollback_index)
{
    UNUSED(ops);
    UNUSED(rollback_index_location);

    /* rollback_index has been checked in bootloader phase.
     * In fs_mgr, returns the smallest value 0 to pass the check.
     */
    *out_rollback_index = 0;
    return AVB_IO_RESULT_OK;
}

static AvbIOResult dummy_validate_vbmeta_public_key(
    AvbOps* ops, const uint8_t* public_key_data, size_t public_key_length,
    const uint8_t* public_key_metadata, size_t public_key_metadata_length,
    bool* out_is_trusted)
{
    UNUSED(ops);
    UNUSED(public_key_data);
    UNUSED(public_key_length);
    UNUSED(public_key_metadata);
    UNUSED(public_key_metadata_length);

    /* vbmeta public key has been checked in bootloader phase.
     * In fs_mgr, returns true to pass the check.
     *
     * Addtionally, fs_mgr should check
     * androidboot.vbmeta.{hash_alg, size, digest} against the digest
     * of all vbmeta images after invoking avb_slot_verify().
     */

    *out_is_trusted = true;
    return AVB_IO_RESULT_OK;
}

static AvbIOResult dummy_read_is_device_unlocked(AvbOps* ops,
                                                 bool* out_is_unlocked)
{
    UNUSED(ops);

    /* The function is for bootloader to update the value into
     * androidboot.vbmeta.device_state in kernel cmdline.
     *
     * In fs_mgr, returns true as we don't need to update it anymore.
     */

    *out_is_unlocked = true;
    return AVB_IO_RESULT_OK;
}

static AvbIOResult dummy_get_unique_guid_for_partition(AvbOps* ops,
                                                       const char* partition,
                                                       char* guid_buf,
                                                       size_t guid_buf_size)
{
    UNUSED(ops);
    UNUSED(partition);

    /* The function is for bootloader to set the correct UUID
     * for a given partition in kernel cmdline.
     *
     * In fs_mgr, returns a faking one as we don't need to update
     * it anymore. */

    snprintf(guid_buf, guid_buf_size, "1234-fake-guid-for:%s", partition);
    return AVB_IO_RESULT_OK;
}

AvbOps* fs_mgr_avb_ops_new(struct fstab* fstab)
{
    AvbOps* ops;
    g_fstab =
        fstab; /* Assign the fstab to the static variable for later use. */

    ops = calloc(1, sizeof(AvbOps));
    if (ops == NULL) {
        ERROR("Error allocating memory for AvbOps.\n");
        goto out;
    }

    /* We only need these operations since that's all what is being used
     * by the avb_slot_verify(); Most of them are dummy operations because
     * they're only required in bootloader but not required in user-space.
     */
    ops->read_from_partition = read_from_partition;
    ops->read_rollback_index = dummy_read_rollback_index;
    ops->validate_vbmeta_public_key = dummy_validate_vbmeta_public_key;
    ops->read_is_device_unlocked = dummy_read_is_device_unlocked;
    ops->get_unique_guid_for_partition = dummy_get_unique_guid_for_partition;

out:
    return ops;
}

void fs_mgr_avb_ops_free(AvbOps* ops) { free(ops); }

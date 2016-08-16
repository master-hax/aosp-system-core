/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "fs_mgr.h"
#include "fs_mgr_priv.h"
#include "libavb.h"

#define SHA256_DIGEST_SIZE 32
#define SHA512_DIGEST_SIZE 64

/* Maximum size of a vbmeta image - 64 KiB. */
#define VBMETA_MAX_SIZE (64 * 1024)

/* Maximum allow length (in bytes) of a partition name,
 * not including A/B suffix.
 */
#define PART_NAME_MAX_SIZE 32

static AvbDescriptor** vbmeta_descriptors = NULL;
static int vbmeta_num_descriptors = 0;
static uint8_t* vbmeta_buf = NULL;

static bool read_from_partition(const char* path, void* buf, size_t num_bytes,
                                size_t* out_num_read) {
    bool ret = false;
    int fd = -1;
    ssize_t num_read;

    fd = TEMP_FAILURE_RETRY(open(path, O_RDONLY | O_CLOEXEC));

    if (fd == -1) {
        ERROR("Failed to open %s (%s)\n", path, strerror(errno));
        goto out;
    }

    /* Linux will never return partial reads when reading from
     * block devices.
     */
    num_read = TEMP_FAILURE_RETRY(read(fd, buf, num_bytes));

    if (num_read == -1) {
        ERROR("Failed to read %zu bytes from %s (%s)\n", num_bytes, path,
              strerror(errno));
        goto out;
    }

    if (out_num_read != NULL) {
        *out_num_read = num_read;
    }

    ret = true;

out:
    if (fd != -1) {
        close(fd);
    }

    return ret;
}

static bool get_vbmeta_hash_info(char* buf, const size_t bufsize,
                                 size_t* out_hash_size) {
    char propbuf[PROPERTY_VALUE_MAX];
    int hash_size;
    int res;

    property_get("ro.boot.vbmeta.hash_alg", propbuf, "");
    if (*propbuf == '\0') {
        ERROR("Failed to get ro.boot.vbmeta.hash_alg\n");
        return false;
    }

    if (0 == strcmp("sha256", propbuf))
        hash_size = SHA256_DIGEST_SIZE;
    else if (0 == strcmp("sha512", propbuf))
        hash_size = SHA512_DIGEST_SIZE;
    else {
        ERROR("Unexpected ro.boot.vbmeta.hash_alg: %s\n", propbuf);
        return false;
    }

    property_get("ro.boot.vbmeta.digest", propbuf, "");
    if (*propbuf == '\0') {
        ERROR("Failed to get ro.boot.vbmeta.digest\n");
        return false;
    }

    res = strlcpy(buf, propbuf, bufsize);
    if (res < 0 || (size_t)res >= bufsize) {
        ERROR("ro.boot.vbmeta.digest too long\n");
        return false;
    }

    if (hash_size != strlen(buf)) {
        ERROR("Wrong length of ro.boot.vbmeta.digest: %d (expected: %d)\n",
              strlen(buf), hash_size);
        return false;
    }

    if (out_hash_size != NULL) {
        *out_hash_size = (size_t)hash_size;
    }

    return true;
}

static bool count_descriptors(const AvbDescriptor* descriptor,
                              void* user_data) {
    size_t* num_descriptors = user_data;

    /* In fs_mgr, we only need to verify dm-verity partitions.
     * The corresponding descriptor might be a CHAIN_PARTITION or a HASHTREE.
     */
    if (descriptor->tag == AVB_DESCRIPTOR_TAG_HASHTREE ||
        descriptor->tag == AVB_DESCRIPTOR_TAG_CHAIN_PARTITION)
        *num_descriptors += 1;

    return true;
}

typedef struct {
    size_t descriptor_number;
    const AvbDescriptor** descriptors;
} SetDescriptorData;

static bool set_descriptors(const AvbDescriptor* descriptor, void* user_data) {
    if (descriptor->tag == AVB_DESCRIPTOR_TAG_HASHTREE ||
        descriptor->tag == AVB_DESCRIPTOR_TAG_CHAIN_PARTITION) {
        SetDescriptorData* data = user_data;
        data->descriptors[data->descriptor_number++] = descriptor;
    }
    return true;
}

static const AvbDescriptor** avb_get_descriptors(const uint8_t* image_data,
                                                 size_t image_size,
                                                 size_t* out_num_descriptors) {
    size_t num_descriptors = 0;
    SetDescriptorData data;

    avb_descriptor_foreach(image_data, image_size, count_descriptors,
                           &num_descriptors);

    data.descriptor_number = 0;
    data.descriptors =
        calloc(sizeof(const AvbDescriptor*) * (num_descriptors + 1));
    if (data.descriptors == NULL) {
        return NULL;
    }
    avb_descriptor_foreach(image_data, image_size, set_descriptors, &data);
    if (data.descriptor_number != num_descriptors) {
        ERROR("data.descriptor_number (%zu) != num_descriptors(%zu)\n",
              data.descriptor_number, num_descriptors);
        return NULL;
    }

    if (out_num_descriptors != NULL) {
        *out_num_descriptors = num_descriptors;
    }

    return data.descriptors;
}

void unload_vbmeta_partition() {
    if (vbmeta_buf != NULL) {
        free(vbmeta_buf);
        vbmeta_buf = NULL;
    }
    if (vbmeta_descriptors != NULL) {
        free(vbmeta_descriptors);
        vbmeta_descriptors = NULL;
    }
    vbmeta_num_descriptors = 0;
}

bool load_vbmeta_partition(struct fstab* fstab) {
    size_t vbmeta_num_read;
    int vbmeta_fd = 0;
    AvbVBMetaImageHeader vbmeta_header;
    char expected_hash[SHA512_DIGEST_SIZE + 1];
    int expected_hash_size;
    const uint8_t* header_block;
    const uint8_t* authentication_block;
    struct fstab_rec* vbmeta_fstab =
        fs_mgr_get_entry_for_mount_point(fstab, "/vbmeta");

    if (vbmeta_fstab == NULL) return false;

    /* Get expected hash value of the vbmeta partition for verification. */
    if (!get_vbmeta_hash_info(expected_hash, sizeof(expected_hash),
                              &expected_hash_size) {
        ERROR("Failed to get expected hash from kernel cmdline\n");
        return false;
    }

    vbmeta_buf = malloc(VBMETA_MAX_SIZE);
    if (vbmeta_buf == NULL) {
        ERROR("Failed to allocate memory for vbmeta partition\n");
        return false;
    }

    WARNING("Loading vbmeta struct from vbmeta partition.\n");
    if (!read_from_partition(vbmeta_fstab->blk_device, vbmeta_buf,
                             VBMETA_MAX_SIZE, &vbmeta_num_read)) {
        ERROR("Failed to read vbmeta partition\n");
        goto fail;
    }

    if (vbmeta_num_read > VBMETA_MAX_SIZE) {
        ERROR("vbmeta_num_read %d exceeds MAX SIZE: %d\n", vbmeta_num_read,
              VBMETA_MAX_SIZE);
        goto fail;
    }

    avb_vbmeta_image_header_to_host_byte_order(
        (const AvbVBMetaImageHeader*)vbmeta_buf, &vbmeta_header);

    /* Checks that the hash in the vbmeta header is the same as that from
     * kernel command line. */
    header_block = vbmeta_buf;
    authentication_block = header_block + sizeof(AvbVBMetaImageHeader);
    if (expected_hash_size != vbmeta_header.hash_size) {
        ERROR("Incorrect hash size: %d (expected: %d)\n",
              vbmeta_header.hash_size, expected_hash_size);
        goto fail;
    }

    if (memcmp(authentication_block + vbmeta_header.hash_offset,
               expected_hash, expected_hash_size) != 0) {
        ERROR("Hash mismatch!\n");
        goto fail;
    }

    /* Check if the image is properly signed. */
    vbmeta_ret = avb_vbmeta_image_verify(vbmeta_buf, vbmeta_num_read,
                                         NULL /* pk_data */, NULL /* pk_len */);
    if (vbmeta_ret != AVB_VBMETA_VERIFY_RESULT_OK) {
        ERROR("Failed to verify vbmeta partition\n");
        goto fail;
    }

    vbmeta_descriptors = avb_get_descriptors(vbmeta_buf, vbmeta_num_read,
                                             &vbmeta_num_descriptors);
    if (vbmeta_descriptors == NULL) {
        ERROR("Failed to get vbmeta descriptors\n");
        goto fail;
    }

    return true;

fail:
    unload_vbmeta_partition();
    return false;
}

AvbDescriptor* get_partition_descriptor(const char* partition_name) {
    AvbDescriptor desc;
    size_t n;

    if (!vbmeta_buf || !vbmeta_descriptors) {
        ERROR(
            "vbmeta partition isn't loaded\n"
            "Please invoke load_vbmeta_partition(fstab *) first\n");
        return NULL;
    }

    for (n = 0; n < vbmeta_num_descriptors; n++) {
        if (!avb_descriptor_validate_and_byteswap(vbmeta_descriptors[n],
                                                  &desc)) {
            WARNING("Descriptor is invalid.\n");
            continue;
        }

        switch (desc.tag) {
            case AVB_DESCRIPTOR_TAG_CHAIN_PARTITION: {
                const uint8_t* chain_partition_name;
                chain_partition_name = ((const uint8_t*)descriptors[n]) +
                                       sizeof(AvbChainPartitionDescriptor);
                if (0 ==
                    strcmp(partition_name, (const char*)chain_partition_name)) {
                    return vbmeta_descriptors[n];
                }
            } break;

            case AVB_DESCRIPTOR_TAG_HASHTREE: {
                const uint8_t* hashtree_partition_name;
                hashtree_partition_name = ((const uint8_t*)descriptors[n]) +
                                          sizeof(AvbHashtreeDescriptor);
                if (0 == strcmp(partition_name,
                                (const char*)hashtree_partition_name)) {
                    return vbmeta_descriptors[n];
                }
            } break;
        }
    }
    return NULL;
}

int fs_mgr_setup_avb(struct fstab_rec* fstab) {
    char part_name[PART_NAME_MAX_SIZE];
    int res = -1;
    AvbDescriptor* desc;
    char* mount_point;

    mount_point = basename(fstab->mount_point);
    res = strlcpy(part_name, mount_point, PART_NAME_MAX_SIZE);
    if (res < 0 || (size_t)res >= PART_NAME_MAX_SIZE) {
        ERROR("mount_point is too long?\n");
        return res;
    }

    desc = get_partition_descriptor(part_name);
    if (desc == NULL) {
        ERROR("AVB descriptor of partition: %s not found\n", part_name);
        return res;
    }

    switch (desc->tag) {
        case AVB_DESCRIPTOR_TAG_CHAIN_PARTITION: {
            const uint8_t* chain_partition_name;
            chain_partition_name = ((const uint8_t*)descriptors[n]) +
                                   sizeof(AvbChainPartitionDescriptor);
            if (0 ==
                strcmp(partition_name, (const char*)chain_partition_name)) {
                return vbmeta_descriptors[n];
            }

            /* Invoke fec_avb_get_hashtree_descriptor() to get HASHTREE
             * descriptor */
        } break;

        case AVB_DESCRIPTOR_TAG_HASHTREE: {
            const uint8_t* hashtree_partition_name;
            hashtree_partition_name = ((const uint8_t*)descriptors[n]) +
                                      sizeof(AvbHashtreeDescriptor);
            if (0 ==
                strcmp(partition_name, (const char*)hashtree_partition_name)) {
                return vbmeta_descriptors[n];
            }
        } break;
    }
    /* Convert HASHTREE descriptor to verity_table_params. */
}

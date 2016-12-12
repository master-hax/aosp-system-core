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
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <vector>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <cutils/properties.h>
#include <libavb/libavb.h>
#include <sys/ioctl.h>
#include <utils/Compat.h>

#include "fs_mgr.h"
#include "fs_mgr_avb_ops.h"
#include "fs_mgr_priv.h"
#include "fs_mgr_priv_avb.h"
#include "fs_mgr_priv_dm_ioctl.h"

#define SHA256_DIGEST_SIZE 32
#define SHA512_DIGEST_SIZE 64

/* Maximum allow length (in bytes) of a partition name,
 * not including A/B suffix.
 */
#define PART_NAME_MAX_SIZE 32

/* dm-verity table format:

 *   <version> <dev> <hash_dev> <data_block_size> <hash_block_size>
 *   <num_data_blocks> <hash_start_block> <algorithm> <digest> <salt>
 */
#define VERITY_TABLE_FORMAT \
    "%u %s %s %u %u "       \
    "%" PRIu64 " %" PRIu64 " %s %s %s"

AvbSlotVerifyData* g_verify_data = NULL;
AvbOps* g_avbops = NULL;

static inline int hex_to_int(char hex)
{
    if (hex >= '0' && hex <= '9')
        return hex - '0';
    else if (hex >= 'a' && hex <= 'f')
        return hex - 'a' + 10;
    else if (hex >= 'A' && hex <= 'F')
        return hex - 'A' + 10;
    else
        return -1;
}

static void process_kernel_cmdline(
    vbmeta_digest_data* digest_data,
    std::function<void(const std::string&, const std::string&,
                       vbmeta_digest_data*)>
        fn)
{
    std::string cmdline;
    android::base::ReadFileToString("/proc/cmdline", &cmdline);

    for (const auto& entry :
         android::base::Split(android::base::Trim(cmdline), " ")) {
        std::vector<std::string> pieces = android::base::Split(entry, "=");
        if (pieces.size() == 2) {
            fn(pieces[0], pieces[1], digest_data);
        }
    }
}

/* imports verfiy data of /vbmeta partition from kernel cmdline.
 * It includes three fields as shown in the following example:
 * - vbmeta.hash_alg=sha256
 * - vbmeta.size=1408
 * - vbmeta.digest=9be9a5b52568...a563c8f099feda3bab3c98c */
static void import_vbmeta_digest_data(const std::string& key,
                                      const std::string& value,
                                      vbmeta_digest_data* digest_data)
{
    if (android::base::StartsWith(key, "vbmeta.hash_alg")) {
        if (value == "sha256" || value == "sha512") {
            strlcpy(digest_data->hash_algorithm, value.c_str(),
                    sizeof(digest_data->hash_algorithm));
        }
    } else if (android::base::StartsWith(key, "vbmeta.size")) {
        if (!android::base::ParseUint(value.c_str(),
                                      &digest_data->vbmeta_size)) {
            digest_data->vbmeta_size = 0;
        }
    } else if (android::base::StartsWith(key, "vbmeta.digest")) {
        /* Convert hex output to integer */
        digest_data->digest_len = value.length() / 2;
        digest_data->digest_value =
            static_cast<uint8_t*>(malloc(digest_data->digest_len));

        if (!digest_data->digest_value) {
            ERROR("Failed to malloc vbmeta.digest\n");
            return;
        }

        for (size_t i = 0; i < digest_data->digest_len; i++) {
            digest_data->digest_value[i] =
                (hex_to_int(value[i * 2]) << 4) + hex_to_int(value[i * 2 + 1]);
        }
    }
}

static int verify_digest_of_vbmeta_images(AvbSlotVerifyData* verify_data,
                                          vbmeta_digest_data* digest_data)
{
    check(verify_data);
    check(verify_data->num_vbmeta_images > 0);
    check(digest_data);

    AvbSHA256Ctx sha256_ctx;
    AvbSHA512Ctx sha512_ctx;
    size_t n, total_size = 0;
    uint8_t* computed_hash = NULL;

    if (!strcmp(digest_data->hash_algorithm, "sha256")) {
        avb_sha256_init(&sha256_ctx);
        for (n = 0; n < verify_data->num_vbmeta_images; n++) {
            avb_sha256_update(&sha256_ctx,
                              verify_data->vbmeta_images[n].vbmeta_data,
                              verify_data->vbmeta_images[n].vbmeta_size);
            total_size += verify_data->vbmeta_images[n].vbmeta_size;
        }
        computed_hash = avb_sha256_final(&sha256_ctx);

    } else if (!strcmp(digest_data->hash_algorithm, "sha512")) {
        avb_sha512_init(&sha512_ctx);
        for (n = 0; n < verify_data->num_vbmeta_images; n++) {
            avb_sha512_update(&sha512_ctx,
                              verify_data->vbmeta_images[n].vbmeta_data,
                              verify_data->vbmeta_images[n].vbmeta_size);
            total_size += verify_data->vbmeta_images[n].vbmeta_size;
            computed_hash = avb_sha512_final(&sha512_ctx);
        }
    } else {
        ERROR("Unknown hash algorithm: %s\n", digest_data->hash_algorithm);
        return -1;
    }

    if (total_size != digest_data->vbmeta_size) {
        ERROR("total vbmeta size mismatch: %d (expected: %d)\n", total_size,
              digest_data->vbmeta_size);
        return -1;
    }

    if (avb_safe_memcmp(digest_data->digest_value, computed_hash,
                        digest_data->digest_len) != 0) {
        ERROR("vbmeta digest mismatch\n");
        return -1;
    }

    return 0;
}

static bool hashtree_load_verity_table(struct dm_ioctl* io,
                                       char* dm_device_name, int fd,
                                       char* blk_device,
                                       AvbHashtreeDescriptor* hashtree_desc,
                                       char* salt, char* root_digest)
{
    verity_ioctl_init(io, dm_device_name, DM_STATUS_TABLE_FLAG);

    /* The buffer consists of [dm_ioctl][dm_target_spec][verity_params]. */
    char* buffer = (char*)io;

    /* Builds the dm_target_spec arguments. */
    struct dm_target_spec* dm_target =
        (struct dm_target_spec*)&buffer[sizeof(struct dm_ioctl)];
    io->target_count = 1;
    dm_target->status = 0;
    dm_target->sector_start = 0;
    dm_target->length = hashtree_desc->image_size / 512;
    strcpy(dm_target->target_type, "verity");

    /* Builds the verity params. */
    char* verity_params =
        buffer + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec);
    size_t bufsize = DM_BUF_SIZE - (verity_params - buffer);
    /* TODO(bowgotsai): add the support of error-handling and ECC. */
    int res =
        snprintf(buffer, bufsize, VERITY_TABLE_FORMAT " 1 ignore_zero_blocks",
                 hashtree_desc->dm_verity_version, blk_device, blk_device,
                 hashtree_desc->data_block_size, hashtree_desc->hash_block_size,
                 hashtree_desc->image_size / hashtree_desc->data_block_size,
                 hashtree_desc->tree_offset / hashtree_desc->hash_block_size,
                 (char*)hashtree_desc->hash_algorithm, root_digest, salt);

    if (res < 0 || (size_t)res >= bufsize) {
        ERROR("Error building verity table; insufficient buffer size?\n");
        return -1;
    }

    /* Sets ext target boundary. */
    verity_params += strlen(verity_params) + 1;
    verity_params = (char*)(((unsigned long)verity_params + 7) & ~8);
    dm_target->next = verity_params - buffer;

    /* Sends the ioctl to load the verity table. */
    if (ioctl(fd, DM_TABLE_LOAD, io)) {
        ERROR("Error loading verity table (%s)\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int hashtree_dm_verity_setup(struct fstab_rec* fstab_entry,
                                    AvbHashtreeDescriptor* hashtree_desc,
                                    char* salt, char* root_digest)
{
    int retval = FS_MGR_SETUP_AVB_FAIL;
    int fd = -1;
    char* verity_blk_name = NULL;

    alignas(dm_ioctl) char buffer[DM_BUF_SIZE];
    struct dm_ioctl* io = (struct dm_ioctl*)buffer;
    char* mount_point = basename(fstab_entry->mount_point);

    /* Gets the device mapper fd. */
    if ((fd = open("/dev/device-mapper", O_RDWR)) < 0) {
        ERROR("Error opening device mapper (%s)\n", strerror(errno));
        goto out;
    }

    /* Creates the device. */
    if (create_verity_device(io, mount_point, fd) < 0) {
        ERROR("Couldn't create verity device!\n");
        goto out;
    }

    /* Gets the name of the device file. */
    if (get_verity_device_name(io, mount_point, fd, &verity_blk_name) < 0) {
        ERROR("Couldn't get verity device number!\n");
        goto out;
    }

    /* Loads the verity mapping table. */
    if (hashtree_load_verity_table(io, mount_point, fd, fstab_entry->blk_device,
                                   hashtree_desc, salt, root_digest) == 0) {
        goto loaded;
    }

loaded:

    /* Activates the device. */
    if (resume_verity_table(io, mount_point, fd) < 0) {
        goto out;
    }

    /* Marks the underlying block device as read-only. */
    fs_mgr_set_blk_ro(fstab_entry->blk_device);

    /* TODO(bowgotsai): support verified all partition at boot. */
    free(fstab_entry->blk_device);
    fstab_entry->blk_device = verity_blk_name;
    verity_blk_name = NULL;

    /* Makes sure we've set everything up properly */
    if (test_access(fstab_entry->blk_device) < 0) {
        goto out;
    }

    retval = FS_MGR_SETUP_AVB_SUCCESS;

out:
    if (fd != -1) {
        close(fd);
    }

    if (verity_blk_name != NULL) {
        free(verity_blk_name);
    }

    return retval;
}

static inline char* hexlify(const uint8_t* input, size_t len)
{
    char* output = new (std::nothrow) char[2 * len + 1];
    if (!output) return NULL;

    for (size_t n = 0; n < len; n++) {
        snprintf(output + 2 * n, 2 + 1 /* size, including the null byte */,
                 "%02x", input[n]);
    }
    return output;
}

static int get_hashtree_descriptor(const char* partition_name,
                                   size_t partition_name_len,
                                   AvbSlotVerifyData* verify_data,
                                   AvbHashtreeDescriptor** out_hashtree_desc,
                                   char** out_digest, char** out_salt)
{
    check(out_hashtree_desc);
    check(out_digest);
    check(out_salt);

    bool found = false;
    const uint8_t* desc_partition_name;

    std::unique_ptr<AvbHashtreeDescriptor> hashtree_desc(
        new (std::nothrow) AvbHashtreeDescriptor);
    check(hashtree_desc);

    for (size_t i = 0; i < verify_data->num_vbmeta_images && !found; i++) {
        /* Get descriptors from vbmeta_images[i] */
        size_t num_descriptors;
        std::unique_ptr<const AvbDescriptor* [], decltype(&avb_free)>
            descriptors(avb_descriptor_get_all(
                            verify_data->vbmeta_images[i].vbmeta_data,
                            verify_data->vbmeta_images[i].vbmeta_size,
                            &num_descriptors),
                        avb_free);

        if (!descriptors || num_descriptors < 1) {
            continue;
        }

        for (size_t j = 0; j < num_descriptors && !found; j++) {
            AvbDescriptor desc;
            if (!avb_descriptor_validate_and_byteswap(descriptors[j], &desc)) {
                WARNING("Descriptor is invalid.\n");
                continue;
            }

            if (desc.tag == AVB_DESCRIPTOR_TAG_HASHTREE) {
                desc_partition_name = (const uint8_t*)descriptors[j] +
                                      sizeof(AvbHashtreeDescriptor);

                if (!avb_hashtree_descriptor_validate_and_byteswap(
                        (AvbHashtreeDescriptor*)descriptors[j],
                        hashtree_desc.get())) {
                    continue;
                }

                if (hashtree_desc->partition_name_len != partition_name_len) {
                    continue;
                }

                if (memcmp(partition_name, (const char*)desc_partition_name,
                           partition_name_len) == 0) {
                    found = true;
                }
            }
        }
    }

    if (!found) {
        ERROR("%s: partition descriptor not found\n", partition_name);
        return -1;
    }

    const uint8_t* desc_salt =
        desc_partition_name + hashtree_desc->partition_name_len;
    *out_salt = hexlify(desc_salt, hashtree_desc->salt_len);
    check(*out_salt);

    const uint8_t* desc_digest = desc_salt + hashtree_desc->salt_len;
    *out_digest = hexlify(desc_digest, hashtree_desc->root_digest_len);
    check(*out_digest);

    *out_hashtree_desc = hashtree_desc.release();

    return 0;
}

int fs_mgr_load_vbmeta_images(struct fstab* fstab)
{
    /* Gets the expected hash value of vbmeta images from kernel
     * cmdline. */
    vbmeta_digest_data digest_data;
    process_kernel_cmdline(&digest_data, import_vbmeta_digest_data);

    uint64_t expected_digest_size = 0;
    if (!strcmp(digest_data.hash_algorithm, "sha256")) {
        expected_digest_size = SHA256_DIGEST_SIZE;
    } else if (!strcmp(digest_data.hash_algorithm, "sha512")) {
        expected_digest_size = SHA512_DIGEST_SIZE;
    } else {
        ERROR("Unknown hash algorithm: %s\n", digest_data.hash_algorithm);
        return FS_MGR_SETUP_AVB_FAIL;
    }
    check(digest_data.digest_len == expected_digest_size);

    g_avbops = fs_mgr_avb_ops_new(fstab);
    check(g_avbops != NULL);

    char propbuf[PROPERTY_VALUE_MAX];
    bool allow_verification_error = false;
    property_get("ro.boot.vbmeta.device_state", propbuf, "");
    if (*propbuf != '\0') {
        if (!strcmp(propbuf, "unlocked")) {
            allow_verification_error = true;
        }
    }

    /* Invokes avb_slot_verify() to load and verify all vbmeta images.
     * Sets requested_partitions to NULL as it's to copy the contents
     * of HASH partitions into g_verify_data, which is not required as
     * fs_mgr only deals with HASHTREE partitions.
     */
    const char* requested_partitions[] = {NULL};
    AvbSlotVerifyResult verify_result =
        avb_slot_verify(g_avbops, requested_partitions, "" /* ab_suffix */,
                        allow_verification_error, &g_verify_data);

    if (verify_digest_of_vbmeta_images(g_verify_data, &digest_data) != 0) {
        goto fail;
    }

    if (allow_verification_error &&
        verify_result == AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION) {
        AvbVBMetaImageHeader vbmeta_header;
        avb_vbmeta_image_header_to_host_byte_order(
            (AvbVBMetaImageHeader*)g_verify_data->vbmeta_images[0].vbmeta_data,
            &vbmeta_header);

        bool hashtree_disabled = ((AvbVBMetaImageFlags)vbmeta_header.flags &
                                  AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED);

        if (hashtree_disabled)
            return FS_MGR_SETUP_AVB_HASHTREE_DISABLED;
        else
            goto fail;

    } else {
        if (verify_result == AVB_SLOT_VERIFY_RESULT_OK)
            return FS_MGR_SETUP_AVB_SUCCESS;
        else
            goto fail;
    }

fail:
    fs_mgr_unload_vbmeta_images();
    return FS_MGR_SETUP_AVB_FAIL;
}

void fs_mgr_unload_vbmeta_images()
{
    if (g_verify_data != NULL) {
        avb_slot_verify_data_free(g_verify_data);
    }

    if (g_avbops != NULL) {
        fs_mgr_avb_ops_free(g_avbops);
    }
}

int fs_mgr_setup_avb(struct fstab_rec* fstab_entry)
{
    int retval = FS_MGR_SETUP_AVB_FAIL;

    if (!g_verify_data || g_verify_data->num_vbmeta_images < 1) {
        return retval;
    }

    char partition_name[PART_NAME_MAX_SIZE];
    char* mount_point = basename(fstab_entry->mount_point);
    size_t partition_name_len =
        strlcpy(partition_name, mount_point, PART_NAME_MAX_SIZE);

    if (partition_name_len >= PART_NAME_MAX_SIZE) {
        ERROR("mount_point: %s is too long?\n", fstab_entry->mount_point);
        return retval;
    }

    if (!avb_validate_utf8((const uint8_t*)partition_name,
                           partition_name_len)) {
        ERROR("Partition name: %s is not valid UTF-8.\n", partition_name);
        return retval;
    }

    AvbHashtreeDescriptor* hashtree_descriptor;
    char* salt = NULL;
    char* root_digest = NULL;
    if (get_hashtree_descriptor((const char*)partition_name, partition_name_len,
                                g_verify_data, &hashtree_descriptor, &salt,
                                &root_digest)) {
        ERROR("Failed to get hashtree descriptor of partition: %s\n",
              partition_name);
        return retval;
    }

    /* Convert HASHTREE descriptor to verity_table_params. */
    if (hashtree_dm_verity_setup(fstab_entry, hashtree_descriptor, salt,
                                 root_digest) != 0) {
        goto out;
    }

    retval = FS_MGR_SETUP_AVB_SUCCESS;

out:
    delete hashtree_descriptor;
    delete[] salt;
    delete[] root_digest;
    return retval;
}

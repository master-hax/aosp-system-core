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
#include <utils/Compat.h>

#include "fs_mgr.h"
#include "fs_mgr_priv.h"
#include "fs_mgr_priv_avb.h"

#define SHA256_DIGEST_SIZE 32
#define SHA512_DIGEST_SIZE 64

/* Maximum size of a vbmeta image - 64 KiB. */
#define VBMETA_MAX_SIZE (64 * 1024)

/* Maximum allow length (in bytes) of a partition name,
 * not including A/B suffix.
 */
#define PART_NAME_MAX_SIZE 32

static bool read_from_partition(const char* path, void* buf, size_t count,
                                int64_t offset, size_t* out_num_read)
{
    bool ret = false;
    int64_t total_size;
    ssize_t num_read;

    int fd = TEMP_FAILURE_RETRY(open(path, O_RDONLY | O_CLOEXEC));

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

    /* Linux will never return partial reads when reading from
     * block devices.
     */
    num_read = TEMP_FAILURE_RETRY(pread64(fd, buf, count, offset));

    if (num_read < 0 || (size_t)num_read != count) {
        ERROR("Failed to read %zu bytes from %s offset %" PRId64 " (%s)\n",
              count, path, offset, strerror(errno));
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
    vbmeta_verify_data* verify_data,
    std::function<void(const std::string&, const std::string&,
                       vbmeta_verify_data*)>
        fn)
{
    std::string cmdline;
    android::base::ReadFileToString("/proc/cmdline", &cmdline);

    for (const auto& entry :
         android::base::Split(android::base::Trim(cmdline), " ")) {
        std::vector<std::string> pieces = android::base::Split(entry, "=");
        if (pieces.size() == 2) {
            fn(pieces[0], pieces[1], verify_data);
        }
    }
}

/* imports verfiy data of /vbmeta partition from kernel cmdline.
 * It includes three fields as shown in the following example:
 * - vbmeta.hash_alg=sha256
 * - vbmeta.size=1408
 * - vbmeta.digest=9be9a5b52568...a563c8f099feda3bab3c98c */
static void import_vbmeta_verify_data(const std::string& key,
                                      const std::string& value,
                                      vbmeta_verify_data* verify_data)
{
    if (android::base::StartsWith(key, "vbmeta.hash_alg")) {
        if (value == "sha256" || value == "sha512") {
            strlcpy(verify_data->hash_algorithm, value.c_str(),
                    sizeof(verify_data->hash_algorithm));
        }
    } else if (android::base::StartsWith(key, "vbmeta.size")) {
        if (!android::base::ParseUint(value.c_str(),
                                      &verify_data->vbmeta_size)) {
            verify_data->vbmeta_size = 0;
        }
    } else if (android::base::StartsWith(key, "vbmeta.digest")) {
        /* Convert hex output to integer */
        verify_data->hash_size = value.length() / 2;
        verify_data->hash_value =
            static_cast<uint8_t*>(malloc(verify_data->hash_size));

        if (!verify_data->hash_value) {
            ERROR("Failed to malloc vbmeta.digest\n");
            return;
        }

        for (size_t i = 0; i < verify_data->hash_size; i++) {
            verify_data->hash_value[i] =
                (hex_to_int(value[i * 2]) << 4) + hex_to_int(value[i * 2 + 1]);
        }
    }
}

int load_and_verify_main_vbmeta(struct fstab* fstab,
                                vbmeta_descriptor_data* desc_data)
{
    struct fstab_rec* vbmeta_fstab =
        fs_mgr_get_entry_for_mount_point(fstab, "/vbmeta");

    check(vbmeta_fstab != NULL);

    /* Gets the expected hash value of vbmeta partition from kernel cmdline. */
    vbmeta_verify_data verify_data;
    process_kernel_cmdline(&verify_data, import_vbmeta_verify_data);

    uint64_t expected_hash_size = 0;
    if (!strcmp(verify_data.hash_algorithm, "sha256")) {
        expected_hash_size = SHA256_DIGEST_SIZE;
    } else if (!strcmp(verify_data.hash_algorithm, "sha512")) {
        expected_hash_size = SHA512_DIGEST_SIZE;
    }

    check(verify_data.hash_size == expected_hash_size);

    std::unique_ptr<uint8_t[]> vbmeta_buf(new (std::nothrow)
                                              uint8_t[VBMETA_MAX_SIZE]);

    if (!vbmeta_buf) {
        ERROR("Failed to allocate memory for vbmeta partition\n");
        return -1;
    }

    size_t vbmeta_num_read;
    if (!read_from_partition(vbmeta_fstab->blk_device, vbmeta_buf.get(),
                             VBMETA_MAX_SIZE, 0 /* offset */,
                             &vbmeta_num_read)) {
        ERROR("Failed to read vbmeta partition\n");
        return -1;
    }

    check(vbmeta_num_read <= VBMETA_MAX_SIZE);

    AvbVBMetaImageHeader vbmeta_header;
    avb_vbmeta_image_header_to_host_byte_order(
        (const AvbVBMetaImageHeader*)vbmeta_buf.get(), &vbmeta_header);

    check(verify_data.hash_size == vbmeta_header.hash_size);

    /* Checks that the hash in the vbmeta header is the same as that from
     * kernel cmdline. */
    const uint8_t* header_block = vbmeta_buf.get();
    const uint8_t* authentication_block =
        header_block + sizeof(AvbVBMetaImageHeader);

    if (memcmp(authentication_block + vbmeta_header.hash_offset,
               verify_data.hash_value, verify_data.hash_size) != 0) {
        ERROR("Hash mismatch!\n");
        return -1;
    }

    /* Check if the image is properly signed. */
    AvbVBMetaVerifyResult vbmeta_ret =
        avb_vbmeta_image_verify(vbmeta_buf.get(), vbmeta_num_read,
                                NULL /* pk_data */, NULL /* pk_len */);

    if (vbmeta_ret != AVB_VBMETA_VERIFY_RESULT_OK) {
        ERROR("Failed to verify vbmeta partition\n");
        return -1;
    }

    size_t num_descriptors;
    std::unique_ptr<const AvbDescriptor*, decltype(&avb_free)> descriptors(
        avb_descriptor_get_all(vbmeta_buf.get(), vbmeta_num_read,
                               &num_descriptors),
        avb_free);

    if (!descriptors || num_descriptors < 1) {
        ERROR("Failed to get descriptors\n");
        return -1;
    }

    desc_data->vbmeta_buf = vbmeta_buf.release();
    desc_data->descriptors = descriptors.release();
    desc_data->num_descriptors = num_descriptors;

    return 0;
}

static int get_vbmeta_offset_and_size(const char* path, size_t* vbmeta_offset,
                                      size_t* vbmeta_size)
{
    uint8_t footer_buf[AVB_FOOTER_SIZE];
    size_t footer_num_read;

    if (!read_from_partition(path, footer_buf, AVB_FOOTER_SIZE /* count*/,
                             -AVB_FOOTER_SIZE /* offset */, &footer_num_read)) {
        ERROR("Error loading footer from: %s\n", path);
        return -1;
    }

    check(footer_num_read == AVB_FOOTER_SIZE);

    AvbFooter footer;
    if (!avb_footer_validate_and_byteswap((const AvbFooter*)footer_buf,
                                          &footer)) {
        ERROR("Error validating footer from: %s\n", path);
        return -1;
    }

    /* Basic footer sanity check since the data is untrusted. */
    check(footer.vbmeta_size <= VBMETA_MAX_SIZE);

    *vbmeta_offset = footer.vbmeta_offset;
    *vbmeta_size = footer.vbmeta_size;

    return 0;
}

static int load_and_verify_footer_vbmeta(const char* blk_device,
                                         const uint8_t* expected_public_key,
                                         size_t expected_public_key_length,
                                         vbmeta_descriptor_data* desc_data)
{
    check(expected_public_key);

    size_t vbmeta_offset;
    size_t vbmeta_size;

    if (get_vbmeta_offset_and_size(blk_device, &vbmeta_offset, &vbmeta_size))
        return -1;

    std::unique_ptr<uint8_t[]> vbmeta_buf(new (std::nothrow)
                                              uint8_t[vbmeta_size]);

    if (!vbmeta_buf) {
        ERROR("%s: failed to allocate memory for footer vbmeta\n", blk_device);
        return -1;
    }

    size_t vbmeta_num_read;
    if (!read_from_partition(blk_device, vbmeta_buf.get(), vbmeta_size,
                             vbmeta_offset, &vbmeta_num_read)) {
        ERROR("%s: failed to read footer vbmeta\n", blk_device);
        return -1;
    }

    check(vbmeta_num_read <= vbmeta_size);

    const uint8_t* pk_data;
    size_t pk_len;

    /* Check if the image is properly signed and get the public key used
     * to sign the image.
     */
    AvbVBMetaVerifyResult vbmeta_ret = avb_vbmeta_image_verify(
        vbmeta_buf.get(), vbmeta_num_read, &pk_data, &pk_len);

    if (vbmeta_ret != AVB_VBMETA_VERIFY_RESULT_OK) {
        ERROR("%s: failed to verify footer vbmeta\n", blk_device);
        return -1;
    }

    /* For footer vbmeta, always checks if key used to make signature
     * matches what is expected. */
    if (expected_public_key_length != pk_len ||
        memcmp(expected_public_key, pk_data, pk_len) != 0) {
        ERROR(
            "%s: public key used to sign data does not match key in chain "
            "partition descriptor\n",
            blk_device);
        return -1;
    }

    size_t num_descriptors;
    std::unique_ptr<const AvbDescriptor*, decltype(&avb_free)> descriptors(
        avb_descriptor_get_all(vbmeta_buf.get(), vbmeta_num_read,
                               &num_descriptors),
        avb_free);

    if (!descriptors) {
        ERROR("%s: failed to get descriptors from footer vbmeta\n", blk_device);
        return -1;
    }

    if (num_descriptors != 1) {
        ERROR("%s: there should be only one partition descriptor but got %d\n",
              blk_device, num_descriptors);

        return -1;
    }

    desc_data->vbmeta_buf = vbmeta_buf.release();
    desc_data->descriptors = descriptors.release();
    desc_data->num_descriptors = num_descriptors;

    return 0;
}

static int load_and_verify_hashtree_descriptor(
    const char* blk_device, const char* partition_name,
    size_t partition_name_len, const AvbDescriptor** descriptors,
    size_t num_descriptors, AvbHashtreeDescriptor* out_hashtree_desc)
{
    check(descriptors);
    check(out_hashtree_desc);

    bool found = false;
    AvbDescriptor desc;
    std::unique_ptr<AvbHashtreeDescriptor> verified_hashtree_desc(
        new (std::nothrow) AvbHashtreeDescriptor);

    for (size_t n = 0; n < num_descriptors && !found; n++) {
        if (!avb_descriptor_validate_and_byteswap(descriptors[n], &desc)) {
            WARNING("Descriptor[%d] is invalid.\n", n);
            continue;
        }

        switch (desc.tag) {
            case AVB_DESCRIPTOR_TAG_CHAIN_PARTITION: {
                const uint8_t* chain_partition_name =
                    (const uint8_t*)descriptors[n] +
                    sizeof(AvbChainPartitionDescriptor);

                if (memcmp(partition_name, (const char*)chain_partition_name,
                           partition_name_len) == 0) {
                    AvbChainPartitionDescriptor chain_desc;

                    if (!avb_chain_partition_descriptor_validate_and_byteswap(
                            (AvbChainPartitionDescriptor*)descriptors[n],
                            &chain_desc)) {
                        ERROR("%s: chain partition descriptor is invalid\n",
                              partition_name);
                        return -1;
                    }

                    if (chain_desc.partition_name_len != partition_name_len) {
                        ERROR(
                            "%s: partition_name_len mismatch: %d "
                            "(expected: %d)\n",
                            partition_name, chain_desc.partition_name_len,
                            partition_name_len);
                        return -1;
                    }

                    vbmeta_descriptor_data footer_vbmeta_desc_data;
                    const uint8_t* chain_public_key =
                        chain_partition_name + chain_desc.partition_name_len;

                    if (load_and_verify_footer_vbmeta(
                            blk_device, chain_public_key,
                            chain_desc.public_key_len,
                            &footer_vbmeta_desc_data) != 0) {
                        ERROR("%s: failed to verify footer vbmeta\n",
                              partition_name);
                        return -1;
                    }

                    if (avb_hashtree_descriptor_validate_and_byteswap(
                            ((const AvbHashtreeDescriptor*)&footer_vbmeta_desc_data
                                 .descriptors[0]),
                            verified_hashtree_desc.get())) {
                        found = true;
                    } else {
                        ERROR("%s: failed to verify hashtree descriptor\n",
                              partition_name);
                    }

                    free(footer_vbmeta_desc_data.descriptors);
                    free(footer_vbmeta_desc_data.vbmeta_buf);
                }
            } break;

            case AVB_DESCRIPTOR_TAG_HASHTREE: {
                const uint8_t* hashtree_partition_name =
                    (const uint8_t*)descriptors[n] +
                    sizeof(AvbHashtreeDescriptor);

                if (memcmp(partition_name, (const char*)hashtree_partition_name,
                           partition_name_len) == 0) {
                    if (!avb_hashtree_descriptor_validate_and_byteswap(
                            (AvbHashtreeDescriptor*)descriptors[n],
                            verified_hashtree_desc.get())) {
                        ERROR("%s: hashtree partition descriptor is invalid\n",
                              partition_name);
                        return -1;
                    }

                    if (verified_hashtree_desc->partition_name_len !=
                        partition_name_len) {
                        ERROR(
                            "%s: partition_name_len mismatch: %d "
                            "(expected: %d)\n",
                            partition_name,
                            verified_hashtree_desc->partition_name_len,
                            partition_name_len);
                        return -1;
                    }

                    found = true;
                }
            } break;
        }
    }

    if (!found) {
        ERROR("%s: partition descriptor not found\n", partition_name);
        return -1;
    }

    out_hashtree_desc = verified_hashtree_desc.release();
    return 0;
}

int fs_mgr_setup_avb(struct fstab_rec* fstab,
                     vbmeta_descriptor_data* main_desc_data)
{
    if (!main_desc_data->descriptors || main_desc_data->num_descriptors < 1) {
        return -1;
    }

    char partition_name[PART_NAME_MAX_SIZE];
    char* mount_point = basename(fstab->mount_point);
    size_t partition_name_len =
        strlcpy(partition_name, mount_point, PART_NAME_MAX_SIZE);

    if (partition_name_len >= PART_NAME_MAX_SIZE) {
        ERROR("mount_point is too long?\n");
        return -1;
    }

    if (!avb_validate_utf8((const uint8_t*)partition_name,
                           partition_name_len)) {
        ERROR("Partition name is not valid UTF-8.\n");
        return -1;
    }

    AvbHashtreeDescriptor hashtree_descriptor;

    if (load_and_verify_hashtree_descriptor(
            fstab->blk_device, (const char*)partition_name, partition_name_len,
            main_desc_data->descriptors, main_desc_data->num_descriptors,
            &hashtree_descriptor)) {
        ERROR("Failed to get hashtree descriptor of partition: %s\n",
              partition_name);
        return -1;
    }

    /* Convert HASHTREE descriptor to verity_table_params. */
    return 0;
}

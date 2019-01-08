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

#pragma once

#include <string>
#include <vector>

#include <android-base/unique_fd.h>
#include <fstab/fstab.h>
#include <libavb/libavb.h>
#include <libdm/dm.h>

#include "fs_avb/fs_avb.h"

namespace android {
namespace fs_mgr {

enum VBMetaVerifyResult {
    kVBMetaVerifyResultOK = 0,
    kVBMetaVerifyResultError = 1,
    kVBMetaVerifyResultErrorVerification = 2,
};

struct ChainInfo {
    std::string partition_name;
    std::string public_key_blob;

    ChainInfo(const std::string& chain_partition_name, const std::string& chain_public_key_blob)
        : partition_name(std::move(chain_partition_name)),
          public_key_blob(std::move(chain_public_key_blob)) {}
};

// AvbHashtreeDescriptor to dm-verity table setup.
bool GetHashtreeDescriptor(const std::string& partition_name,
                           const std::vector<VBMetaData>& vbmeta_images,
                           AvbHashtreeDescriptor* out_hashtree_desc, std::string* out_salt,
                           std::string* out_digest);

bool ConstructVerityTable(const AvbHashtreeDescriptor& hashtree_desc, const std::string& salt,
                          const std::string& root_digest, const std::string& blk_device,
                          android::dm::DmTable* table);

bool HashtreeDmVeritySetup(FstabEntry* fstab_entry, const AvbHashtreeDescriptor& hashtree_desc,
                           const std::string& salt, const std::string& root_digest,
                           bool wait_for_verity_dev);

// Maps AVB partition name to a device partition name.
std::string AvbPartitionToDevicePatition(const std::string& avb_partition_name,
                                         const std::string& ab_suffix,
                                         const std::string& ab_other_suffix);

// AvbFooter and AvbMetaImage maninpulations.
off64_t GetTotalSize(const android::base::unique_fd& fd);

std::unique_ptr<AvbFooter> GetAvbFooter(const android::base::unique_fd& fd);

std::unique_ptr<VBMetaData> VerifyVBMetaData(const android::base::unique_fd& fd,
                                             const std::string& partition_name,
                                             const std::string& expected_public_key_blob,
                                             VBMetaVerifyResult* out_verify_result);

VBMetaVerifyResult VerifyVBMetaSignature(const VBMetaData& vbmeta,
                                         const std::string& expected_public_key_blob);

bool VerifyPublicKeyBlob(const uint8_t* key, size_t length, const std::string& expected_key_blob);

// Detects if whether a partition contains a rollback image.
bool RollbackDetected(const std::string& partition_name, uint64_t rollback_index);

// Extracts chain partition info.
std::vector<ChainInfo> GetChainPartitionInfo(const VBMetaData& vbmeta, bool* fatal_error);

VBMetaVerifyResult LoadAndVerifyVbmetaImpl(
        const std::string& partition_name, const std::string& ab_suffix,
        const std::string& ab_other_suffix, const std::string& expected_public_key_blob,
        bool allow_verification_error, bool load_chained_vbmeta, bool rollback_protection,
        std::function<std::string(const std::string&)> device_path_constructor,
        bool is_chained_vbmeta, std::vector<VBMetaData>* out_vbmeta_images);

}  // namespace fs_mgr
}  // namespace android

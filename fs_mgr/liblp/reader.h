/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef LIBLP_READER_H_
#define LIBLP_READER_H_

#include <stddef.h>

#include <memory>

#include <liblp/liblp.h>
#include <libvbmeta/super_avb_footer_format.h>
#include <libvbmeta/super_footer_format.h>

namespace android {
namespace fs_mgr {

// Parse an LpMetadataGeometry from a buffer. The buffer must be at least
// LP_METADATA_GEOMETRY_SIZE bytes in size.
bool ParseGeometry(const void* buffer, LpMetadataGeometry* geometry);

// Helper functions for manually reading geometry and metadata.
std::unique_ptr<LpMetadata> ParseMetadata(const LpMetadataGeometry& geometry, int fd);
std::unique_ptr<LpMetadata> ParseMetadata(const LpMetadataGeometry& geometry, const void* buffer,
                                          size_t size);
bool ReadLogicalPartitionGeometry(int fd, LpMetadataGeometry* geometry);
bool ReadPrimaryGeometry(int fd, LpMetadataGeometry* geometry);
bool ReadBackupGeometry(int fd, LpMetadataGeometry* geometry);

// These functions assume a valid geometry and slot number, and do not obey
// auto-slot-suffixing. They are used for tests and for checking whether
// the metadata is coherent across primary and backup copies.
std::unique_ptr<LpMetadata> ReadPrimaryMetadata(int fd, const LpMetadataGeometry& geometry,
                                                uint32_t slot_number);
std::unique_ptr<LpMetadata> ReadBackupMetadata(int fd, const LpMetadataGeometry& geometry,
                                               uint32_t slot_number);

bool ParseSuperAvbFooter(const void *buffer, SuperAVBFooter *footer);
bool ReadSuperAvbFooter(int fd, uint64_t offset, SuperAVBFooter *footer);
bool ParseSuperFooter(const void *buffer, SuperFooter *footer);
bool ReadSuperFooter(int fd, uint64_t super_size, SuperFooter *footer);
uint8_t ReadDataFromSuper(int fd, uint64_t offset);

}  // namespace fs_mgr
}  // namespace android

#endif /* LIBLP_READER_H_ */

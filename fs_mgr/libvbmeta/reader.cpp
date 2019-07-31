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

#include <libvbmeta/reader.h>

#include <android-base/file.h>

#include "utility.h"

namespace android {
namespace fs_mgr {

bool ParseSuperVBMetaHeader(const void *buffer, SuperVBMetaHeader *header) {
  memcpy(header, buffer, sizeof(*header));

  // Do basic validation of super footer.
  if (header->magic != SUPER_VBMETA_MAGIC) {
    LERROR << "Super VBMeta has invalid magic value.";
    return false;
  }

  // Check that the version is compatible.
  if (header->major_version != SUPER_VBMETA_MAJOR_VERSION ||
      header->minor_version > SUPER_VBMETA_MINOR_VERSION) {
    LERROR << "Super Avb Footer has incompatible version.";
    return false;
  }

  return true;
}

bool ParseSuperVBMetaDescriptor(
    const void *buffer, uint32_t size,
    std::vector<SuperVBMetaDescriptor> *descriptors) {
  for (int p = 0; p < size;) {
    SuperVBMetaDescriptor descriptor;
    memcpy(&descriptor, (char *)buffer + p, SUPER_VBMETA_DESCRIPTOR_SIZE);
    p += SUPER_VBMETA_DESCRIPTOR_SIZE;

    descriptor.partition_name =
        (char *)malloc(sizeof(char) * descriptor.partition_name_length);
    memset(descriptor.partition_name, 0, descriptor.partition_name_length);
    memcpy(descriptor.partition_name, (char *)buffer + p,
           descriptor.partition_name_length);
    p += descriptor.partition_name_length;

    descriptors->emplace_back(std::move(descriptor));
  }
  return true;
}

bool ReadSuperVBMeta(int fd, uint64_t offset, SuperVBMeta *vbmeta) {
  if (lseek(fd, offset, SEEK_SET) < 0) {
    PERROR << __PRETTY_FUNCTION__ << " lseek failed";
    return false;
  }

  std::unique_ptr<uint8_t[]> header_buffer =
      std::make_unique<uint8_t[]>(SUPER_VBMETA_HEADER_SIZE);
  if (!android::base::ReadFully(fd, header_buffer.get(),
                                SUPER_VBMETA_HEADER_SIZE)) {
    PERROR << __PRETTY_FUNCTION__ << " super vbmeta read "
           << SUPER_VBMETA_HEADER_SIZE << " bytes failed";
    return false;
  }

  bool rv = ParseSuperVBMetaHeader(header_buffer.get(), &vbmeta->header);

  if (lseek(fd, offset + vbmeta->header.header_size, SEEK_SET) < 0) {
    PERROR << __PRETTY_FUNCTION__ << " lseek failed";
    return false;
  }
  std::unique_ptr<uint8_t[]> descriptors_buffer =
      std::make_unique<uint8_t[]>(vbmeta->header.descriptors_size);
  if (!android::base::ReadFully(fd, descriptors_buffer.get(),
                                vbmeta->header.descriptors_size)) {
    PERROR << __PRETTY_FUNCTION__ << " super vbmeta read "
           << vbmeta->header.descriptors_size << " bytes failed";
    return false;
  }

  return rv & ParseSuperVBMetaDescriptor(descriptors_buffer.get(),
                                         vbmeta->header.descriptors_size,
                                         &vbmeta->descriptors);
}

bool ReadSuperPrimaryVBMeta(int fd, SuperVBMeta *vbmeta) {
  uint64_t offset = GetPrimaryVBMetaOffset();
  return ReadSuperVBMeta(fd, offset, vbmeta);
}

bool ReadSuperBackupVBMeta(int fd, SuperVBMeta *vbmeta,
                           uint64_t super_vbmeta_size) {
  uint64_t offset = GetBackupVBMetaOffset(super_vbmeta_size);
  return ReadSuperVBMeta(fd, offset, vbmeta);
}

uint8_t ReadDataFromSuper(int fd, uint64_t offset) {
  if (lseek(fd, offset, SEEK_SET) < 0) {
    PERROR << __PRETTY_FUNCTION__ << " lseek failed";
    return false;
  }
  std::unique_ptr<uint8_t> buffer = std::make_unique<uint8_t>();
  if (!android::base::ReadFully(fd, buffer.get(), sizeof(uint8_t))) {
    PERROR << __PRETTY_FUNCTION__ << " super footer read " << sizeof(uint8_t)
           << " bytes failed";
    return false;
  }
  return *buffer;
}

} // namespace fs_mgr
} // namespace android

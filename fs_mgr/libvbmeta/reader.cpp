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

#include "libvbmeta/reader.h"
#include "utility.h"

#include <android-base/file.h>
#include <endian.h>
#include <unistd.h>

namespace android {
namespace fs_mgr {

bool ParseSuperAvbFooterHeader(const void *buffer,
                               SuperAVBFooterHeader *header) {
  memcpy(header, buffer, sizeof(*header));

  // Do basic validation of super footer.
  if (header->magic != SUPER_AVB_FOOTER_MAGIC) {
    LERROR << "Super Avb Footer has invalid magic value.";
    return false;
  }

  // Check that the version is compatible.
  if (header->major_version != SUPER_AVB_FOOTER_MAJOR_VERSION ||
      header->minor_version > SUPER_AVB_FOOTER_MINOR_VERSION) {
    LERROR << "Super Avb Footer has incompatible version.";
    return false;
  }
  return true;
}

bool ParseSuperAvbFooterDescriptor(const void *buffer, uint32_t size,
                                   std::vector<VBMetaDescriptor> *descriptors) {
  for (int p = 0; p < size;) {
    VBMetaDescriptor descriptor;
    memcpy(&descriptor, (char *)buffer + p, SUPER_AVB_FOOTER_DESCRIPTOR_SIZE);
    p += SUPER_AVB_FOOTER_DESCRIPTOR_SIZE;

    descriptor.partition_name =
        (char *)malloc(sizeof(char) * descriptor.partition_name_length);
    memcpy(descriptor.partition_name, (char *)buffer + p,
           descriptor.partition_name_length);
    p += descriptor.partition_name_length;

    descriptors->emplace_back(std::move(descriptor));
  }
  return true;
}

bool ReadSuperAvbFooter(int fd, uint64_t offset, SuperAVBFooter *footer) {
  if (lseek(fd, offset, SEEK_SET) < 0) {
    PERROR << __PRETTY_FUNCTION__ << " lseek failed";
    return false;
  }
  std::unique_ptr<uint8_t[]> header_buffer =
      std::make_unique<uint8_t[]>(SUPER_AVB_FOOTER_HEADER_SIZE);
  if (!android::base::ReadFully(fd, header_buffer.get(),
                                SUPER_AVB_FOOTER_HEADER_SIZE)) {
    PERROR << __PRETTY_FUNCTION__ << " super footer read "
           << SUPER_AVB_FOOTER_HEADER_SIZE << " bytes failed";
    return false;
  }

  bool rv = ParseSuperAvbFooterHeader(header_buffer.get(), &footer->header);

  if (lseek(fd, offset + footer->header.header_size, SEEK_SET) < 0) {
    PERROR << __PRETTY_FUNCTION__ << " lseek failed";
    return false;
  }
  std::unique_ptr<uint8_t[]> descriptors_buffer =
      std::make_unique<uint8_t[]>(footer->header.descriptors_size);
  if (!android::base::ReadFully(fd, descriptors_buffer.get(),
                                footer->header.descriptors_size)) {
    PERROR << __PRETTY_FUNCTION__ << " super footer read "
           << footer->header.descriptors_size << " bytes failed";
    return false;
  }
  return rv & ParseSuperAvbFooterDescriptor(descriptors_buffer.get(),
                                            footer->header.descriptors_size,
                                            &footer->descriptors);
}

bool ParseSuperFooter(const void *buffer, SuperFooter *footer) {
  static_assert(sizeof(*footer) <= SUPER_FOOTER_SIZE);
  memcpy(footer, buffer, sizeof(*footer));

  // Do basic validation of super footer.
  if (footer->magic != SUPER_FOOTER_MAGIC) {
    LERROR << "Super Footer has invalid magic value.";
    return false;
  }

  // Check that the version is compatible.
  if (footer->major_version != SUPER_FOOTER_MAJOR_VERSION ||
      footer->minor_version > SUPER_FOOTER_MINOR_VERSION) {
    LERROR << "Super Footer has incompatible version.";
    return false;
  }

  return true;
}
bool ReadSuperFooter(int fd, uint64_t super_size, SuperFooter *footer) {
  uint64_t offset = super_size - SUPER_FOOTER_SIZE;
  if (lseek(fd, offset, SEEK_SET) < 0) {
    PERROR << __PRETTY_FUNCTION__ << " lseek failed";
    return false;
  }
  std::unique_ptr<uint8_t[]> buffer =
      std::make_unique<uint8_t[]>(SUPER_FOOTER_SIZE);
  if (!android::base::ReadFully(fd, buffer.get(), SUPER_FOOTER_SIZE)) {
    PERROR << __PRETTY_FUNCTION__ << " super footer read " << SUPER_FOOTER_SIZE
           << " bytes failed";
    return false;
  }
  return ParseSuperFooter(buffer.get(), footer);
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

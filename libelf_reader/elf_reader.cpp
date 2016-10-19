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

#include <elf_reader/elf_reader.h>

#include <errno.h>
#include <string.h>

#include <android-base/stringprintf.h>

using android::base::StringPrintf;

namespace android {
namespace libelf_reader {

std::unique_ptr<ElfReader> ElfReader::OpenFile(const char* filename, size_t file_offset,
                                               std::string* error_msg) {
  FILE* fp = fopen(filename, "reb");
  if (fp == nullptr) {
    *error_msg = StringPrintf("fopen(%s) failed: %s", filename, strerror(errno));
    return nullptr;
  }
  if (file_offset != 0u) {
    if (fseek(fp, file_offset, SEEK_SET) != 0) {
      *error_msg = StringPrintf("fseek(%s) failed: %s", filename, strerror(errno));
      fclose(fp);
      return nullptr;
    }
  }
  unsigned char buf[EI_NIDENT];
  if (fread(buf, sizeof(buf), 1, fp) != 1) {
    *error_msg = StringPrintf("fread(%s) failed: %s", filename, strerror(errno));
    fclose(fp);
    return nullptr;
  }
  if (memcmp(buf, ELFMAG, 4) == 0) {
    if (buf[EI_CLASS] == ELFCLASS32) {
      ElfReader32* impl = new ElfReader32(filename, fp, file_offset);
      return std::unique_ptr<ElfReader>(new ElfReader(impl));
    } else if (buf[EI_CLASS] == ELFCLASS64) {
      ElfReader64* impl = new ElfReader64(filename, fp, file_offset);
      return std::unique_ptr<ElfReader>(new ElfReader(impl));
    }
  }
  *error_msg = StringPrintf("%s is not an elf file", filename);
  fclose(fp);
  return nullptr;
}

std::unique_ptr<ElfReader> ElfReader::OpenMem(const char* data, size_t size, const char* mem_name,
                                              std::string* error_msg) {
  if (size >= EI_NIDENT) {
    if (memcmp(data, ELFMAG, 4) == 0) {
      if (data[EI_CLASS] == ELFCLASS32) {
        ElfReader32* impl = new ElfReader32(data, size, mem_name);
        return std::unique_ptr<ElfReader>(new ElfReader(impl));
      } else if (data[EI_CLASS] == ELFCLASS64) {
        ElfReader64* impl = new ElfReader64(data, size, mem_name);
        return std::unique_ptr<ElfReader>(new ElfReader(impl));
      }
    }
  }
  *error_msg = StringPrintf("%s is not an elf file", mem_name);
  return nullptr;
}

}  // namespace libelf_reader
}  // namespace android

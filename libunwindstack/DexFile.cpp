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

#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>

#include <android-base/unique_fd.h>

#include <unwindstack/DexFileHooks.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Memory.h>

#include "DexFile.h"

namespace unwindstack {

DexFile::~DexFile() {
  if (dex_file_ != nullptr) {
    hooks::FreeDexFile(dex_file_);
  }
}

DexFile* DexFile::Create(uint64_t dex_file_offset_in_memory, Memory* memory, MapInfo* info) {
  if (!info->name.empty()) {
    std::unique_ptr<DexFileFromFile> dex_file(new DexFileFromFile);
    if (dex_file->Open(dex_file_offset_in_memory - info->start + info->offset, info->name)) {
      return dex_file.release();
    }
  }

  std::unique_ptr<DexFileFromMemory> dex_file(new DexFileFromMemory);
  if (dex_file->Open(dex_file_offset_in_memory, memory)) {
    return dex_file.release();
  }
  return nullptr;
}

bool DexFile::GetMethodInformation(uint64_t dex_offset, std::string* method_name,
                                   uint64_t* method_offset) {
  if (dex_file_ == nullptr) {
    return false;
  }

  // The method data is cached in a std::map indexed by method end offset and
  // contains the start offset and the method member index.
  // Only cache the method data for matching methods so that anything doing
  // multiple unwinds will have this data cached for future use, but don't cache
  // all methods.

  // First look in the method cache.
  auto entry = method_cache_.upper_bound(dex_offset);
  if (entry != method_cache_.end() && dex_offset >= entry->second.first) {
    *method_name = entry->second.second;
    *method_offset = dex_offset - entry->second.first;
    return true;
  }

  std::string name;
  uint64_t offset_start, offset_end;
  if (hooks::GetMethodInformation(dex_file_, dex_offset, &name, &offset_start, &offset_end)) {
    method_cache_[offset_end] = std::make_pair(offset_start, name);
    if (offset_start <= dex_offset && dex_offset < offset_end) {
      *method_name = name;
      *method_offset = dex_offset - offset_start;
      return true;
    }
  }
  return false;
}

bool DexFileFromFile::Open(uint64_t dex_file_offset_in_file, const std::string& file) {
  return hooks::DexFileFromFile(&dex_file_, dex_file_offset_in_file, file);
}

bool DexFileFromMemory::Open(uint64_t dex_file_offset_in_memory, Memory* memory) {
  for (size_t size = 0;;) {
    size = hooks::DexFileFromMemory(&dex_file_, memory_.data(), size);
    if (size <= 0) {
      return size == 0;
    }
    memory_.resize(size);
    if (!memory->ReadFully(dex_file_offset_in_memory, memory_.data(), memory_.size())) {
      return false;
    }
  }
}

}  // namespace unwindstack

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
    GetDexFileHooks()->FreeDexFile(dex_file_);
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

  const char* name;
  if (!GetDexFileHooks()->GetMethodInformation(dex_file_, dex_offset, &name, method_offset)) {
    return false;
  }
  *method_name = std::string(name);
  return true;
}

bool DexFileFromFile::Open(uint64_t dex_file_offset_in_file, const std::string& file) {
  return GetDexFileHooks()->DexFileFromFile(&dex_file_, dex_file_offset_in_file, file.c_str());
}

bool DexFileFromMemory::Open(uint64_t dex_file_offset_in_memory, Memory* memory) {
  const DexFileHooks* hooks = GetDexFileHooks();
  for (int64_t size = 0;;) {
    size = hooks->DexFileFromMemory(&dex_file_, memory_.data(), size);
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

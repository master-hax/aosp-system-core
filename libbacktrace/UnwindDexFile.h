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

#ifndef _LIBBACKTRACE_UNWIND_DEX_FILE_H
#define _LIBBACKTRACE_UNWIND_DEX_FILE_H

#include <stdint.h>

// Forward declarations.
namespace art {
class DexFile;
};

namespace unwindstack {
class Memory;
struct MapInfo;
};  // namespace unwindstack

class UnwindDexFile {
 public:
  UnwindDexFile() = default;
  virtual ~UnwindDexFile();

  static UnwindDexFile* Create(uint64_t dex_file_offset, unwindstack::Memory* memory,
                               unwindstack::MapInfo* info);

  void GetMethodInformation(uint64_t dex_offset, std::string* method_name, uint64_t* method_offset);

 protected:
  const art::DexFile* dex_file_ = nullptr;
};

class UnwindDexFileFromFile : public UnwindDexFile {
 public:
  UnwindDexFileFromFile() = default;
  virtual ~UnwindDexFileFromFile();

  bool Open(uint64_t dex_file_offset, const std::string& name);

 private:
  void* mapped_memory_ = nullptr;
  size_t size_ = 0;
};

class UnwindDexFileFromMemory : public UnwindDexFile {
 public:
  UnwindDexFileFromMemory() = default;
  virtual ~UnwindDexFileFromMemory();

  bool Open(uint64_t dex_file_offset, unwindstack::Memory* memory);

 private:
  uint8_t* memory_ = nullptr;
};

#endif  // _LIBBACKTRACE_UNWIND_DEX_FILE_H

/*
 * Copyright 2020 The Android Open Source Project
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

#include <functional>
#include <iostream>
#include <vector>

#include <unwindstack/DexFiles.h>
#include <unwindstack/Maps.h>

#include "UnwindComponentCreator.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace unwindstack {

// 100 * 50 = 5kb
static constexpr int kMaxLibraries = 100;
static constexpr int kMaxLibNameLen = 50;

static constexpr int kMaxMemorySize = 3000;
static constexpr int kMaxFileName = 200;

static constexpr int kMaxOperations = 30;
typedef std::vector<std::function<void(FuzzedDataProvider*, DexFiles*)>> OperationVec;

OperationVec getOperations() {
  OperationVec operations = {
      [](FuzzedDataProvider* data_provider, DexFiles* dex) -> void {
        uint64_t ptr_offset = data_provider->ConsumeIntegral<uint64_t>();
        // Map info
        uint64_t map_start = data_provider->ConsumeIntegral<uint64_t>();
        uint64_t map_end = data_provider->ConsumeIntegral<uint64_t>();
        uint64_t map_offset = data_provider->ConsumeIntegral<uint64_t>();
        uint64_t memory_flags = data_provider->ConsumeIntegral<uint64_t>();
        std::string filename = data_provider->ConsumeRandomLengthString(kMaxFileName);
        std::unique_ptr<MapInfo> map_info = std::make_unique<MapInfo>(
            nullptr, nullptr, map_start, map_end, map_offset, memory_flags, filename.c_str());
        dex->GetDexFile(ptr_offset, map_info.get());
      },
      [](FuzzedDataProvider* data_provider, DexFiles* dex) -> void {
        uint16_t bytes_size = data_provider->ConsumeIntegral<uint16_t>();

        std::vector<char> maps_blob = data_provider->ConsumeBytes<char>(bytes_size);
        const char* blob = maps_blob.data();
        std::unique_ptr<Maps> maps = GetMaps(blob);
        uint64_t dex_pc = data_provider->ConsumeIntegral<uint64_t>();
        uint64_t method_offset;
        std::string out_val;
        dex->GetMethodInformation(maps.get(), maps->Get(0), dex_pc, &out_val, &method_offset);
      },
  };
  return operations;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  OperationVec operations = getOperations();
  FuzzedDataProvider data_provider(data, size);
  uint16_t mem_len = data_provider.ConsumeIntegralInRange<uint16_t>(0, kMaxMemorySize);
  std::vector<uint8_t> mem_vec = data_provider.ConsumeBytes<uint8_t>(mem_len);

  std::shared_ptr<Memory> memory = Memory::CreateOfflineMemory(mem_vec.data(), 0, mem_len);

  std::unique_ptr<DexFiles> dex_files =
      GetDexFiles(&data_provider, memory, kMaxLibraries, kMaxLibNameLen);

  int ops_run = 0;
  while (data_provider.remaining_bytes() > 0 && ops_run++ < kMaxOperations) {
    uint8_t op = data_provider.ConsumeIntegralInRange<uint8_t>(0, operations.size() - 1);
    operations[op](&data_provider, dex_files.get());
  }
  return 0;
}
}  // namespace unwindstack

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

#include <unwindstack/Memory.h>

#include "MemoryOfflineBuffer.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace unwindstack {

static constexpr int kMaxMemorySize = 5000;
static constexpr int kMaxOperations = 100;
typedef std::vector<std::function<void(FuzzedDataProvider*, Memory*)>> OperationVec;

OperationVec getOperations() {
  OperationVec operations = {
      [](FuzzedDataProvider*, Memory* mem) -> void { mem->Clear(); },
      [](FuzzedDataProvider*, Memory* mem) -> void { mem->IsLocal(); },
      [](FuzzedDataProvider* data_provider, Memory* mem) -> void {
        uint64_t addr = data_provider->ConsumeIntegral<uint64_t>();
        size_t max_read = data_provider->ConsumeIntegral<size_t>();
        std::unique_ptr<std::string> out_str = std::make_unique<std::string>();
        mem->ReadString(addr, out_str.get(), max_read);
      },
      [](FuzzedDataProvider* data_provider, Memory* mem) -> void {
        uint64_t addr = data_provider->ConsumeIntegral<uint64_t>();
        size_t max_read = data_provider->ConsumeIntegral<size_t>();
        uint16_t out_buf_size = data_provider->ConsumeIntegralInRange<uint16_t>(0, kMaxMemorySize);
        std::vector<uint8_t> out(out_buf_size);
        mem->ReadFully(addr, out.data(), max_read);
      },
      [](FuzzedDataProvider* data_provider, Memory* mem) -> void {
        uint64_t addr = data_provider->ConsumeIntegral<uint64_t>();
        mem->ReadTag(addr);
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
  int ops_run = 0;
  while (data_provider.remaining_bytes() > 0 && ops_run++ < kMaxOperations) {
    uint8_t op = data_provider.ConsumeIntegralInRange<uint8_t>(0, operations.size() - 1);
    operations[op](&data_provider, memory.get());
  }
  return 0;
}
}  // namespace unwindstack

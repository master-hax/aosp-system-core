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

#include <unwindstack/Memory.h>

#include <iostream>
#include <memory>

#include "MemoryOfflineBuffer.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace unwindstack {

static constexpr int kMaxMemorysize = 5000;
static constexpr int MAX_OPERATIONS = 100;
typedef std::vector<std::function<void(FuzzedDataProvider*, Memory*)>> OperationVec;

OperationVec getOperations() {
  OperationVec operations = {
      [](FuzzedDataProvider*, Memory* mem) -> void { mem->Clear(); },
      [](FuzzedDataProvider*, Memory* mem) -> void { mem->IsLocal(); },
      [](FuzzedDataProvider* dataProvider, Memory* mem) -> void {
        uint64_t addr = dataProvider->ConsumeIntegral<uint64_t>();
        size_t maxRead = dataProvider->ConsumeIntegral<size_t>();
        std::unique_ptr<std::string> outStr = std::make_unique<std::string>();
        mem->ReadString(addr, outStr.get(), maxRead);
      },
      [](FuzzedDataProvider* dataProvider, Memory* mem) -> void {
        uint64_t addr = dataProvider->ConsumeIntegral<uint64_t>();
        size_t maxRead = dataProvider->ConsumeIntegral<size_t>();
        uint8_t out;
        mem->ReadFully(addr, &out, maxRead);
      },
      [](FuzzedDataProvider* dataProvider, Memory* mem) -> void {
        uint64_t addr = dataProvider->ConsumeIntegral<uint64_t>();
        mem->ReadTag(addr);
      },
  };
  return operations;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  OperationVec operations = getOperations();
  FuzzedDataProvider dataProvider(data, size);
  uint16_t memLen = dataProvider.ConsumeIntegralInRange<uint16_t>(0, kMaxMemorysize);
  std::vector<uint8_t> memVec = dataProvider.ConsumeBytes<uint8_t>(memLen);

  std::shared_ptr<Memory> memory = Memory::CreateOfflineMemory(memVec.data(), 0, memLen);
  int opsRun = 0;
  while (dataProvider.remaining_bytes() > 0 && opsRun++ < MAX_OPERATIONS) {
    uint8_t op = dataProvider.ConsumeIntegralInRange<uint8_t>(0, operations.size() - 1);
    operations[op](&dataProvider, memory.get());
  }
  return 0;
}
}  // namespace unwindstack

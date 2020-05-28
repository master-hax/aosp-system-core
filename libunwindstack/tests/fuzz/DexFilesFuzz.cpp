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

#include <unwindstack/DexFiles.h>
#include <unwindstack/Maps.h>

#include <iostream>

#include "UnwindComponentCreator.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace unwindstack {

// 100 * 50 = 5kb
static constexpr int kMaxLibraries = 100;
static constexpr int kMaxLibNameLen = 50;

static constexpr int kMaxMemorysize = 3000;
static constexpr int kMaxFileName = 200;
static constexpr int kMaxOperations = 100;
typedef std::vector<std::function<void(FuzzedDataProvider*, DexFiles*)>> OperationVec;

OperationVec getOperations() {
  OperationVec operations = {
      [](FuzzedDataProvider* dataProvider, DexFiles* dex) -> void {
        uint64_t ptrOffset = dataProvider->ConsumeIntegral<uint64_t>();
        // Map info
        uint64_t mapStart = dataProvider->ConsumeIntegral<uint64_t>();
        uint64_t mapEnd = dataProvider->ConsumeIntegral<uint64_t>();
        uint64_t mapOffset = dataProvider->ConsumeIntegral<uint64_t>();
        uint64_t memoryFlags = dataProvider->ConsumeIntegral<uint64_t>();
        std::string filename = dataProvider->ConsumeRandomLengthString(kMaxFileName);
        std::unique_ptr<MapInfo> mapInfo = std::make_unique<MapInfo>(
            nullptr, nullptr, mapStart, mapEnd, mapOffset, memoryFlags, filename.c_str());
        dex->GetDexFile(ptrOffset, mapInfo.get());
      },
      [](FuzzedDataProvider* dataProvider, DexFiles* dex) -> void {
        uint16_t bytesSize = dataProvider->ConsumeIntegral<uint16_t>();

        std::vector<char> mapsBlob = dataProvider->ConsumeBytes<char>(bytesSize);
        const char* blob = mapsBlob.data();
        std::unique_ptr<Maps> maps = GetMaps(blob);
        uint64_t dexPc = dataProvider->ConsumeIntegral<uint64_t>();
        uint64_t methodOffset;
        std::string outVal;
        dex->GetMethodInformation(maps.get(), maps->Get(0), dexPc, &outVal, &methodOffset);
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

  std::unique_ptr<DexFiles> dexFiles =
      GetDexFiles(&dataProvider, memory, kMaxLibraries, kMaxLibNameLen);

  int opsRun = 0;
  while (dataProvider.remaining_bytes() > 0 && opsRun++ < kMaxOperations) {
    uint8_t op = dataProvider.ConsumeIntegralInRange<uint8_t>(0, operations.size() - 1);
    operations[op](&dataProvider, dexFiles.get());
  }
  return 0;
}
}  // namespace unwindstack

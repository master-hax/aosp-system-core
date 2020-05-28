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

#include <unwindstack/JitDebug.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Unwinder.h>

#include <iostream>

#include "UnwindComponentCreator.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace unwindstack {

// 100 * 50 = 5kb of data. May be too much in the long run.
// At most could be 5kb * maxOperations, so 500kb
static constexpr int kMaxLibraries = 100;
static constexpr int kMaxLibNameLen = 50;

static constexpr int kMaxMemorysize = 5000;
static constexpr int kMaxOperations = 100;

std::shared_ptr<Memory> genMem(FuzzedDataProvider* dataProvider) {
  uint16_t memLen = dataProvider->ConsumeIntegralInRange<uint16_t>(0, kMaxMemorysize);
  std::vector<uint8_t> memVec = dataProvider->ConsumeBytes<uint8_t>(memLen);
  std::shared_ptr<Memory> memory = Memory::CreateOfflineMemory(memVec.data(), 0, memLen);
  return memory;
}

typedef std::vector<std::function<void(FuzzedDataProvider*, Unwinder*)>> OperationVec;

// This was not made static to ensure the destructor is called.
OperationVec getOperations() {
  OperationVec operations = {
      [](FuzzedDataProvider*, Unwinder* unwinder) -> void { unwinder->NumFrames(); },
      [](FuzzedDataProvider*, Unwinder* unwinder) -> void { unwinder->ConsumeFrames(); },
      [](FuzzedDataProvider*, Unwinder* unwinder) -> void { unwinder->GetMaps(); },
      [](FuzzedDataProvider*, Unwinder* unwinder) -> void { unwinder->LastErrorCode(); },
      [](FuzzedDataProvider*, Unwinder* unwinder) -> void { unwinder->LastErrorAddress(); },
      [](FuzzedDataProvider*, Unwinder* unwinder) -> void { unwinder->elf_from_memory_not_file(); },
      [](FuzzedDataProvider* dataProvider, Unwinder* unwinder) -> void {
        unwinder->SetResolveNames(dataProvider->ConsumeBool());
      },
      [](FuzzedDataProvider* dataProvider, Unwinder* unwinder) -> void {
        unwinder->SetEmbeddedSoname(dataProvider->ConsumeBool());
      },
      [](FuzzedDataProvider* dataProvider, Unwinder* unwinder) -> void {
        unwinder->SetDisplayBuildID(dataProvider->ConsumeBool());
      },
      [](FuzzedDataProvider* dataProvider, Unwinder* unwinder) -> void {
        size_t frame = dataProvider->ConsumeIntegral<size_t>();
        unwinder->FormatFrame(frame);
      },
      [](FuzzedDataProvider* dataProvider, Unwinder* unwinder) -> void {
        size_t frame = dataProvider->ConsumeIntegral<size_t>();
        unwinder->FormatFrame(frame);
      },
      [](FuzzedDataProvider* dataProvider, Unwinder* unwinder) -> void {
        uint64_t pc = dataProvider->ConsumeIntegral<uint64_t>();
        unwinder->BuildFrameFromPcOnly(pc);
      },
      [](FuzzedDataProvider* dataProvider, Unwinder* unwinder) -> void {
        std::shared_ptr<Memory> memory = genMem(dataProvider);

        std::unique_ptr<DexFiles> dexFiles =
            GetDexFiles(dataProvider, memory, kMaxLibraries, kMaxLibNameLen);
        uint8_t arch = dataProvider->ConsumeIntegralInRange<uint8_t>(1, kArchCount);
        unwinder->SetDexFiles(dexFiles.get(), static_cast<ArchEnum>(arch));
      },
      [](FuzzedDataProvider* dataProvider, Unwinder* unwinder) -> void {
        std::shared_ptr<Memory> memory = genMem(dataProvider);
        int libCount = dataProvider->ConsumeIntegralInRange<uint>(0, kMaxLibraries);

        std::unique_ptr<JitDebug> jitDebug;
        if (libCount == 0) {
          jitDebug = std::make_unique<JitDebug>(memory);
        } else {
          std::vector<std::string> searchLibs = std::vector<std::string>();
          for (int i = 0; i < libCount; i++) {
            searchLibs.push_back(dataProvider->ConsumeRandomLengthString(kMaxLibNameLen));
          }

          jitDebug = std::make_unique<JitDebug>(memory, searchLibs);
        }
        uint8_t arch = dataProvider->ConsumeIntegralInRange<uint8_t>(1, kArchCount);
        unwinder->SetJitDebug(jitDebug.get(), static_cast<ArchEnum>(arch));
      },
  };
  return operations;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider dataProvider(data, size);
  OperationVec operations = getOperations();

  // First we need to construct an unwinder
  // Unwinder(size_t max_frames, Maps* maps, Regs* regs, std::shared_ptr<Memory>
  // process_memory)
  size_t maxFrames = dataProvider.ConsumeIntegralInRange<size_t>(0, 5000);

  size_t bufferLen = dataProvider.ConsumeIntegral<size_t>();
  std::string buffer = dataProvider.ConsumeBytesAsString(bufferLen);
  std::unique_ptr<Maps> maps = GetMaps(buffer.data());

  uint8_t arch = dataProvider.ConsumeIntegralInRange<uint8_t>(1, kArchCount);
  std::unique_ptr<Regs> regs = GetRegisters(static_cast<ArchEnum>(arch));

  std::shared_ptr<Memory> memory = genMem(&dataProvider);

  std::unique_ptr<Unwinder> unwinder =
      std::make_unique<Unwinder>(maxFrames, maps.get(), regs.get(), memory);

  int opsRun = 0;
  while (dataProvider.remaining_bytes() > 0 && opsRun++ < kMaxOperations) {
    uint8_t op = dataProvider.ConsumeIntegralInRange<uint8_t>(0, operations.size() - 1);
    operations[op](&dataProvider, unwinder.get());
  }
  return 0;
}
}  // namespace unwindstack

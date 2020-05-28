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

#include <unwindstack/JitDebug.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Unwinder.h>

#include "UnwindComponentCreator.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace unwindstack {

// 100 * 50 = 5kb of data. May be too much in the long run.
// At most could be 5kb * maxOperations, so 500kb
static constexpr int kMaxLibraries = 100;
static constexpr int kMaxLibNameLen = 50;

static constexpr int kMaxMemorySize = 5000;
static constexpr int kMaxOperations = 100;

std::shared_ptr<Memory> genMem(FuzzedDataProvider* data_provider) {
  uint16_t memLen = data_provider->ConsumeIntegralInRange<uint16_t>(0, kMaxMemorySize);
  std::vector<uint8_t> memVec = data_provider->ConsumeBytes<uint8_t>(memLen);
  std::shared_ptr<Memory> memory = Memory::CreateOfflineMemory(memVec.data(), 0, memLen);
  return memory;
}

typedef std::vector<std::function<void(FuzzedDataProvider*, Unwinder*)>> OperationVec;

// This was not made static to ensure the destructor is called.
OperationVec getOperations() {
  OperationVec operations = {
      [](FuzzedDataProvider*, Unwinder* unwinder) -> void { unwinder->Unwind(); },
      [](FuzzedDataProvider*, Unwinder* unwinder) -> void { unwinder->NumFrames(); },
      [](FuzzedDataProvider*, Unwinder* unwinder) -> void { unwinder->ConsumeFrames(); },
      [](FuzzedDataProvider*, Unwinder* unwinder) -> void { unwinder->GetMaps(); },
      [](FuzzedDataProvider*, Unwinder* unwinder) -> void { unwinder->LastErrorCode(); },
      [](FuzzedDataProvider*, Unwinder* unwinder) -> void { unwinder->LastErrorAddress(); },
      [](FuzzedDataProvider*, Unwinder* unwinder) -> void { unwinder->elf_from_memory_not_file(); },
      [](FuzzedDataProvider* data_provider, Unwinder* unwinder) -> void {
        unwinder->SetResolveNames(data_provider->ConsumeBool());
      },
      [](FuzzedDataProvider* data_provider, Unwinder* unwinder) -> void {
        unwinder->SetEmbeddedSoname(data_provider->ConsumeBool());
      },
      [](FuzzedDataProvider* data_provider, Unwinder* unwinder) -> void {
        unwinder->SetDisplayBuildID(data_provider->ConsumeBool());
      },
      [](FuzzedDataProvider* data_provider, Unwinder* unwinder) -> void {
        size_t frame = data_provider->ConsumeIntegral<size_t>();
        unwinder->FormatFrame(frame);
      },
      [](FuzzedDataProvider* data_provider, Unwinder* unwinder) -> void {
        size_t frame = data_provider->ConsumeIntegral<size_t>();
        unwinder->FormatFrame(frame);
      },
      [](FuzzedDataProvider* data_provider, Unwinder* unwinder) -> void {
        uint64_t pc = data_provider->ConsumeIntegral<uint64_t>();
        unwinder->BuildFrameFromPcOnly(pc);
      },
      [](FuzzedDataProvider* data_provider, Unwinder* unwinder) -> void {
        std::shared_ptr<Memory> memory = genMem(data_provider);

        std::unique_ptr<DexFiles> dex_files =
            GetDexFiles(data_provider, memory, kMaxLibraries, kMaxLibNameLen);
        uint8_t arch = data_provider->ConsumeIntegralInRange<uint8_t>(1, kArchCount);
        unwinder->SetDexFiles(dex_files.get(), static_cast<ArchEnum>(arch));
      },
      [](FuzzedDataProvider* data_provider, Unwinder* unwinder) -> void {
        std::shared_ptr<Memory> memory = genMem(data_provider);
        int lib_count = data_provider->ConsumeIntegralInRange<uint>(0, kMaxLibraries);

        std::unique_ptr<JitDebug> jit_debug;
        if (lib_count == 0) {
          jit_debug = std::make_unique<JitDebug>(memory);
        } else {
          std::vector<std::string> search_libs = std::vector<std::string>();
          for (int i = 0; i < lib_count; i++) {
            search_libs.push_back(data_provider->ConsumeRandomLengthString(kMaxLibNameLen));
          }

          jit_debug = std::make_unique<JitDebug>(memory, search_libs);
        }
        uint8_t arch = data_provider->ConsumeIntegralInRange<uint8_t>(1, kArchCount);
        unwinder->SetJitDebug(jit_debug.get(), static_cast<ArchEnum>(arch));
      },
  };
  return operations;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider data_provider(data, size);
  OperationVec operations = getOperations();

  // First we need to construct an unwinder
  // Unwinder(size_t max_frames, Maps* maps, Regs* regs, std::shared_ptr<Memory>
  // process_memory)
  size_t max_frames = data_provider.ConsumeIntegralInRange<size_t>(0, 5000);

  size_t buffer_len = data_provider.ConsumeIntegral<size_t>();
  std::string buffer = data_provider.ConsumeBytesAsString(buffer_len);
  std::unique_ptr<Maps> maps = GetMaps(buffer.data());

  uint8_t arch = data_provider.ConsumeIntegralInRange<uint8_t>(1, kArchCount);
  std::unique_ptr<Regs> regs = GetRegisters(static_cast<ArchEnum>(arch));

  std::shared_ptr<Memory> memory = genMem(&data_provider);

  std::unique_ptr<Unwinder> unwinder =
      std::make_unique<Unwinder>(max_frames, maps.get(), regs.get(), memory);

  int ops_run = 0;
  while (data_provider.remaining_bytes() > 0 && ops_run++ < kMaxOperations) {
    uint8_t op = data_provider.ConsumeIntegralInRange<uint8_t>(0, operations.size() - 1);
    operations[op](&data_provider, unwinder.get());
  }
  return 0;
}
}  // namespace unwindstack

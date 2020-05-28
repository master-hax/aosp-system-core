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

#include <unwindstack/Elf.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>
#include <unwindstack/RegsArm.h>
#include <unwindstack/RegsArm64.h>
#include <unwindstack/RegsX86.h>
#include <unwindstack/RegsX86_64.h>

#include <iostream>
#include <memory>

#include "UnwindComponentCreator.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace unwindstack {

static constexpr int kMaxMemorySize = 1000;
static constexpr int kMaxOperations = 30;
typedef std::vector<std::function<void(FuzzedDataProvider*, Regs*, Memory*, Memory*)>> OperationVec;

// This was not made static to ensure the destructor is called.
OperationVec getOperations() {
  OperationVec operations = {
      [](FuzzedDataProvider*, Regs* regs, Memory*, Memory*) -> void { regs->Arch(); },
      [](FuzzedDataProvider*, Regs*, Memory*, Memory*) -> void { Regs::CurrentArch(); },
      [](FuzzedDataProvider*, Regs* regs, Memory*, Memory*) -> void { regs->RawData(); },
      [](FuzzedDataProvider*, Regs* regs, Memory*, Memory*) -> void { regs->Is32Bit(); },
      [](FuzzedDataProvider*, Regs* regs, Memory*, Memory*) -> void { regs->pc(); },
      [](FuzzedDataProvider*, Regs* regs, Memory*, Memory*) -> void { regs->sp(); },
      [](FuzzedDataProvider*, Regs* regs, Memory*, Memory*) -> void { regs->dex_pc(); },
      [](FuzzedDataProvider* dataProvider, Regs* regs, Memory*, Memory*) -> void {
        regs->set_pc(dataProvider->ConsumeIntegral<uint64_t>());
      },
      [](FuzzedDataProvider* dataProvider, Regs* regs, Memory*, Memory*) -> void {
        regs->set_sp(dataProvider->ConsumeIntegral<uint64_t>());
      },
      [](FuzzedDataProvider* dataProvider, Regs* regs, Memory*, Memory*) -> void {
        regs->set_dex_pc(dataProvider->ConsumeIntegral<uint64_t>());
      },
      [](FuzzedDataProvider*, Regs* regs, Memory*, Memory*) -> void { regs->total_regs(); },
      [](FuzzedDataProvider* dataProvider, Regs*, Memory*, Memory*) -> void {
        Regs* regs = Regs::RemoteGet(dataProvider->ConsumeIntegral<pid_t>());
        delete regs;
      },
      [](FuzzedDataProvider*, Regs*, Memory*, Memory*) -> void {
        Regs* regs = Regs::CreateFromLocal();
        delete regs;
      },
      [](FuzzedDataProvider*, Regs* regs, Memory*, Memory*) -> void {
        regs->IterateRegisters([&](const char*, uint64_t) {});
      },
      [](FuzzedDataProvider*, Regs* regs, Memory* procMem, Memory*) -> void {
        regs->SetPcFromReturnAddress(procMem);
      },
      [](FuzzedDataProvider* dataProvider, Regs* regs, Memory* procMem, Memory* elfMem) -> void {
        std::unique_ptr<Elf> elf = std::make_unique<Elf>(elfMem);
        regs->StepIfSignalHandler(dataProvider->ConsumeIntegral<uint64_t>(), elf.get(), procMem);
        elf.release();
      }};
  return operations;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider dataProvider(data, size);
  uint8_t arch = dataProvider.ConsumeIntegralInRange<uint8_t>(1, kArchCount);
  OperationVec operations = getOperations();
  std::unique_ptr<Regs> reg = GetRegisters(static_cast<ArchEnum>(arch));

  // Process Memory:
  int procMemSize = dataProvider.ConsumeIntegralInRange<int>(1, kMaxMemorySize);
  std::vector<uint8_t> procMemBlob = dataProvider.ConsumeBytes<uint8_t>(procMemSize);
  std::shared_ptr<Memory> procMem = Memory::CreateOfflineMemory(procMemBlob.data(), 0, procMemSize);

  // Elf Memory:
  int elfMemSize = dataProvider.ConsumeIntegralInRange<int>(1, kMaxMemorySize);
  std::vector<uint8_t> elfMemBlob = dataProvider.ConsumeBytes<uint8_t>(elfMemSize);
  std::shared_ptr<Memory> elfMem = Memory::CreateOfflineMemory(elfMemBlob.data(), 0, elfMemSize);

  // Run operations on Regs using memory
  int opsRun = 0;
  while (dataProvider.remaining_bytes() > 0 && opsRun++ < kMaxOperations) {
    uint8_t op = dataProvider.ConsumeIntegralInRange<uint8_t>(0, operations.size() - 1);
    operations[op](&dataProvider, reg.get(), elfMem.get(), procMem.get());
  }
  return 0;
}
}  // namespace unwindstack

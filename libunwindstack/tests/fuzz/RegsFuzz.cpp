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

#include <unwindstack/Elf.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>
#include <unwindstack/RegsArm.h>
#include <unwindstack/RegsArm64.h>
#include <unwindstack/RegsX86.h>
#include <unwindstack/RegsX86_64.h>
#include "MemoryOfflineBuffer.h"

#include "UnwindComponentCreator.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace unwindstack {

static constexpr int kMaxMemorySize = 1000;
static constexpr int kMaxOperations = 30;
typedef std::vector<std::function<void(FuzzedDataProvider*, Regs*, Memory*, Elf*)>> OperationVec;

// This was not made static to ensure the destructor is called.
OperationVec getOperations() {
  OperationVec operations = {
      [](FuzzedDataProvider*, Regs* regs, Memory*, Elf*) -> void { regs->Arch(); },
      [](FuzzedDataProvider*, Regs*, Memory*, Elf*) -> void { Regs::CurrentArch(); },
      [](FuzzedDataProvider*, Regs* regs, Memory*, Elf*) -> void { regs->RawData(); },
      [](FuzzedDataProvider*, Regs* regs, Memory*, Elf*) -> void { regs->Is32Bit(); },
      [](FuzzedDataProvider*, Regs* regs, Memory*, Elf*) -> void { regs->pc(); },
      [](FuzzedDataProvider*, Regs* regs, Memory*, Elf*) -> void { regs->sp(); },
      [](FuzzedDataProvider*, Regs* regs, Memory*, Elf*) -> void { regs->dex_pc(); },
      [](FuzzedDataProvider* data_provider, Regs* regs, Memory*, Elf*) -> void {
        regs->set_pc(data_provider->ConsumeIntegral<uint64_t>());
      },
      [](FuzzedDataProvider* data_provider, Regs* regs, Memory*, Elf*) -> void {
        regs->set_sp(data_provider->ConsumeIntegral<uint64_t>());
      },
      [](FuzzedDataProvider* data_provider, Regs* regs, Memory*, Elf*) -> void {
        regs->set_dex_pc(data_provider->ConsumeIntegral<uint64_t>());
      },
      [](FuzzedDataProvider*, Regs* regs, Memory*, Elf*) -> void { regs->total_regs(); },
      [](FuzzedDataProvider* data_provider, Regs*, Memory*, Elf*) -> void {
        Regs* regs = Regs::RemoteGet(data_provider->ConsumeIntegral<pid_t>());
        delete regs;
      },
      [](FuzzedDataProvider*, Regs*, Memory*, Elf*) -> void {
        Regs* regs = Regs::CreateFromLocal();
        delete regs;
      },
      [](FuzzedDataProvider*, Regs* regs, Memory*, Elf*) -> void {
        regs->IterateRegisters([&](const char*, uint64_t) {});
      },
      [](FuzzedDataProvider*, Regs* regs, Memory* proc_mem, Elf*) -> void {
        regs->SetPcFromReturnAddress(proc_mem);
      },
      [](FuzzedDataProvider* data_provider, Regs* regs, Memory* proc_mem, Elf* elf) -> void {
        regs->StepIfSignalHandler(data_provider->ConsumeIntegral<uint64_t>(), elf, proc_mem);
      }};
  return operations;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider data_provider(data, size);
  uint8_t arch = data_provider.ConsumeIntegralInRange<uint8_t>(1, kArchCount);
  OperationVec operations = getOperations();
  std::unique_ptr<Regs> reg = GetRegisters(static_cast<ArchEnum>(arch));

  // Process Memory:
  int proc_mem_size = data_provider.ConsumeIntegralInRange<int>(1, kMaxMemorySize);
  std::vector<uint8_t> proc_mem_blob = data_provider.ConsumeBytes<uint8_t>(proc_mem_size);
  std::shared_ptr<Memory> proc_mem =
      Memory::CreateOfflineMemory(proc_mem_blob.data(), 0, proc_mem_size);

  // Elf Memory:
  int elf_mem_size = data_provider.ConsumeIntegralInRange<int>(1, kMaxMemorySize);
  std::vector<uint8_t> elf_mem_blob = data_provider.ConsumeBytes<uint8_t>(elf_mem_size);
  std::unique_ptr<Memory> elf_mem =
      std::make_unique<MemoryOfflineBuffer>(elf_mem_blob.data(), 0, elf_mem_size);
  Elf elf(elf_mem.release());

  // Run operations on Regs using memory
  int ops_run = 0;
  while (data_provider.remaining_bytes() > 0 && ops_run++ < kMaxOperations) {
    uint8_t op = data_provider.ConsumeIntegralInRange<uint8_t>(0, operations.size() - 1);
    operations[op](&data_provider, reg.get(), proc_mem.get(), &elf);
  }

  return 0;
}
}  // namespace unwindstack

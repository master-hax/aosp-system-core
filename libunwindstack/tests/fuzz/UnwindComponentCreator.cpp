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

#include "UnwindComponentCreator.h"

#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

std::unique_ptr<unwindstack::Regs> GetRegisters(unwindstack::ArchEnum arch) {
  switch (arch) {
    case unwindstack::ARCH_ARM: {
      std::unique_ptr<unwindstack::RegsArm> regs = std::make_unique<unwindstack::RegsArm>();
      return regs;
    }
    case unwindstack::ARCH_ARM64: {
      std::unique_ptr<unwindstack::RegsArm64> regs = std::make_unique<unwindstack::RegsArm64>();
      return regs;
    }
    case unwindstack::ARCH_X86: {
      std::unique_ptr<unwindstack::RegsX86> regs = std::make_unique<unwindstack::RegsX86>();
      return regs;
    }
    case unwindstack::ARCH_X86_64: {
      std::unique_ptr<unwindstack::RegsX86_64> regs = std::make_unique<unwindstack::RegsX86_64>();
      return regs;
    }
    case unwindstack::ARCH_MIPS: {
      std::unique_ptr<unwindstack::RegsMips> regs = std::make_unique<unwindstack::RegsMips>();
      return regs;
    }
    case unwindstack::ARCH_MIPS64: {
      std::unique_ptr<unwindstack::RegsMips64> regs = std::make_unique<unwindstack::RegsMips64>();
      return regs;
    }
    case unwindstack::ARCH_UNKNOWN:
    default: {
      std::unique_ptr<unwindstack::RegsX86_64> regs = std::make_unique<unwindstack::RegsX86_64>();
      return regs;
    }
  }
}
std::unique_ptr<unwindstack::Maps> GetMaps(const char* buffer) {
  return std::make_unique<unwindstack::BufferMaps>(buffer);
}

std::unique_ptr<unwindstack::DexFiles> GetDexFiles(FuzzedDataProvider* dataProvider,
                                                   std::shared_ptr<unwindstack::Memory> memory,
                                                   uint maxLibraries, uint maxLibLength) {
  uint libCount = dataProvider->ConsumeIntegralInRange<uint>(0, maxLibraries);

  std::unique_ptr<unwindstack::DexFiles> dexFiles;
  if (libCount == 0) {
    dexFiles = std::make_unique<unwindstack::DexFiles>(memory);
  } else {
    std::vector<std::string> searchLibs = std::vector<std::string>();
    for (uint i = 0; i < libCount; i++) {
      searchLibs.push_back(dataProvider->ConsumeRandomLengthString(maxLibLength));
    }

    dexFiles = std::make_unique<unwindstack::DexFiles>(memory, searchLibs);
  }
  return dexFiles;
}

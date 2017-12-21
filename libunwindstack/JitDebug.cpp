/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <stdint.h>
#include <sys/mman.h>

#include <memory>
#include <vector>

#include <unwindstack/Elf.h>
#include <unwindstack/JitDebug.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>

namespace unwindstack {

struct JITCodeEntry {
  JITCodeEntry* next_;
  JITCodeEntry* prev_;
  const uint8_t* symfile_addr_;
  uint64_t symfile_size_;
};

struct JITDescriptor {
  uint32_t version_;
  uint32_t action_flag_;
  JITCodeEntry* relevant_entry_;
  JITCodeEntry* first_entry_;
};

JitDebug::JitDebug(std::shared_ptr<Memory>& memory, std::vector<std::string>* search_libs)
    : memory_(memory), search_libs_(search_libs) {}

JitDebug::~JitDebug() {
  for (auto* elf : elf_list_) {
    delete elf;
  }
}

void JitDebug::Init(Maps* maps) {
  if (initialized_) {
    return;
  }

  std::string descriptor_name("__jit_debug_descriptor");
  uint64_t descriptor_addr = 0;
  for (MapInfo* info : *maps) {
    if (!(info->flags & PROT_EXEC) || info->offset != 0) {
      continue;
    }

    if (search_libs_ != nullptr) {
      bool found = false;
      const char* lib = basename(info->name.c_str());
      for (std::string& name : *search_libs_) {
        if (strcmp(name.c_str(), lib) == 0) {
          found = true;
          break;
        }
      }
      if (!found) {
        continue;
      }
    }

    Elf* elf = info->GetElf(memory_, true);
    if (elf->GetGlobalVariable(descriptor_name, &descriptor_addr)) {
      descriptor_addr += info->start;
      break;
    }
  }

  if (descriptor_addr == 0) {
    return;
  }

  // The only portion of the descriptor we care about is the first_entry_
  // field. However, read the entire structure to verify this isn't random
  // memory.
  JITDescriptor desc;
  if (!memory_->ReadFully(descriptor_addr, &desc, sizeof(desc))) {
    return;
  }

  if (desc.version_ != 1 || desc.first_entry_ == nullptr) {
    // Either unknown version, or no jit entries.
    return;
  }

  entry_addr_ = reinterpret_cast<uint64_t>(desc.first_entry_);
}

Elf* JitDebug::GetElf(Maps* maps, uint64_t pc) {
  if (!initialized_) {
    Init(maps);
  }

  // Search the existing elf object first.
  for (Elf* elf : elf_list_) {
    if (elf->IsValidPc(pc)) {
      return elf;
    }
  }

  while (entry_addr_ != 0) {
    // Search the cached elf files first.
    JITCodeEntry code;
    if (!memory_->ReadFully(entry_addr_, &code, sizeof(code))) {
      return nullptr;
    }

    entry_addr_ = reinterpret_cast<uint64_t>(code.next_);

    uint64_t start = reinterpret_cast<uint64_t>(code.symfile_addr_);
    Elf* elf = new Elf(new MemoryRange(memory_, start, code.symfile_size_, 0));
    elf->Init(true);
    if (!elf->valid()) {
      // The data is not formatted in a way we understand, do not attempt
      // any further unwinding.
      entry_addr_ = 0;
      delete elf;
      return nullptr;
    }
    elf_list_.push_back(elf);

    if (elf->IsValidPc(pc)) {
      return elf;
    }
  }
  return nullptr;
}

}  // namespace unwindstack

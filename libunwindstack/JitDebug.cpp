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
#include <cstddef>

#include <atomic>
#include <map>
#include <memory>
#include <unordered_set>
#include <vector>

#include <unwindstack/Elf.h>
#include <unwindstack/JitDebug.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>

// This implements the JIT Compilation Interface.
// See https://sourceware.org/gdb/onlinedocs/gdb/JIT-Interface.html

namespace unwindstack {

// 32-bit platforms may differ in alignment of uint64_t.
struct Uint64_P {
  uint64_t value;
} __attribute__((packed));
struct Uint64_A {
  uint64_t value;
} __attribute__((aligned(8)));

template <typename PointerT, typename Uint64_T>
class JitDebugImpl : public JitDebug {
 public:
  static constexpr const char* kDescriptorMagic = "Android1";
  static constexpr int kMaxRaceRetries = 16;

  struct JITCodeEntry {
    PointerT next;
    PointerT prev;
    PointerT symfile_addr;
    Uint64_T symfile_size;
    // Android-specific extensions.
    Uint64_T register_timestamp;
  };

  struct JITDescriptor {
    uint32_t version;
    uint32_t action_flag;
    PointerT relevant_entry;
    PointerT first_entry;
    // Android-specific extensions:
    uint8_t magic[8];
    uint32_t flags;
    uint32_t sizeof_descriptor;
    uint32_t sizeof_entry;
    uint32_t action_counter;
    uint64_t action_timestamp;
  };

  Elf* GetElf(Maps* maps, uint64_t pc) override;

  void Init(Maps* maps);
  bool SafeRead(uint64_t addr, void* dst, size_t size, bool* race, uint32_t counter);
  bool ReadEntries(bool* race);
  bool ReadEntries(bool detect_races = true);

  bool initialized_ = false;
  uint64_t descriptor_addr_ = 0;
  uint64_t counter_addr_ = 0;

  struct CacheEntry {
    uint64_t timestamp_ = 0;
    uint64_t text_addr_ = 0;
    uint64_t text_size_ = 0;
    std::unique_ptr<Elf> elf_;
    std::unique_ptr<MemoryBuffer> buffer_;
  };
  // Cached entries sorted by the *end* address of the valid PC range.
  std::map<uint64_t, std::unique_ptr<CacheEntry>> entries_;
  // All entries at or before this timestamp have been already cached.
  uint64_t max_timestamp;
};

std::unique_ptr<JitDebug> JitDebug::Create(ArchEnum arch, std::shared_ptr<Memory>& memory,
                                           std::vector<std::string> search_libs) {
  std::unique_ptr<JitDebug> jit;
  switch (arch) {
    case ARCH_X86:
      static_assert(sizeof(JitDebugImpl<uint32_t, Uint64_P>::JITCodeEntry) == 28, "layout");
      jit.reset(new JitDebugImpl<uint32_t, Uint64_P>());
      break;
    case ARCH_ARM:
    case ARCH_MIPS:
      static_assert(sizeof(JitDebugImpl<uint32_t, Uint64_A>::JITCodeEntry) == 32, "layout");
      jit.reset(new JitDebugImpl<uint32_t, Uint64_A>());
      break;
    case ARCH_ARM64:
    case ARCH_X86_64:
    case ARCH_MIPS64:
      static_assert(sizeof(JitDebugImpl<uint64_t, Uint64_A>::JITCodeEntry) == 40, "layout");
      jit.reset(new JitDebugImpl<uint64_t, Uint64_A>());
      break;
    default:
      abort();
  }
  jit->arch_ = arch;
  jit->memory_ = memory;
  jit->search_libs_ = std::move(search_libs);
  return jit;
}

template <typename PointerT, typename SymSizeT>
Elf* JitDebugImpl<PointerT, SymSizeT>::GetElf(Maps* maps, uint64_t pc) {
  std::lock_guard<std::mutex> guard(lock_);
  Init(maps);
  if (!ReadEntries()) {
    return nullptr;
  }
  // Upper bound returns the first entry for which (end > pc).
  auto ub = entries_.upper_bound(pc);
  if (ub != entries_.end() && ub->second->elf_->IsValidPc(pc)) {
    return ub->second->elf_.get();
  }
  return nullptr;
}

template <typename PointerT, typename SymSizeT>
void JitDebugImpl<PointerT, SymSizeT>::Init(Maps* maps) {
  if (initialized_) {
    return;
  }
  // Regardless of what happens below, consider the init finished.
  initialized_ = true;

  const std::string descriptor_name("__jit_debug_descriptor");
  for (MapInfo* info : *maps) {
    if (!(info->flags & PROT_EXEC) || !(info->flags & PROT_READ) || info->offset != 0) {
      continue;
    }

    if (!search_libs_.empty()) {
      bool found = false;
      const char* lib = basename(info->name.c_str());
      for (std::string& name : search_libs_) {
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
    uint64_t descriptor_addr;
    if (elf->GetGlobalVariable(descriptor_name, &descriptor_addr)) {
      JITDescriptor desc;
      descriptor_addr += info->start;
      if (!memory_->ReadFully(descriptor_addr, &desc, sizeof(desc))) {
        continue;
      }
      // Find the first descriptor that has any entries.
      if (desc.first_entry != 0) {
        descriptor_addr_ = descriptor_addr;
        counter_addr_ = descriptor_addr_ + offsetof(JITDescriptor, action_counter);
        break;
      }
    }
  }
}

// Check for race: with a live process it is possible that the memory of the entry
// has been freed and reused for something else before we have managed to read it.
// We can use the action counter to check whether such race might have occurred.
template <typename PointerT, typename SymSizeT>
bool JitDebugImpl<PointerT, SymSizeT>::SafeRead(uint64_t addr, void* dst, size_t size, bool* race,
                                                uint32_t expected_counter) {
  bool ok = memory_->ReadFully(addr, dst, size);
  if (race != nullptr) {
    uint32_t seen_counter;
    std::atomic_thread_fence(std::memory_order_acquire);
    if (!memory_->Read32(counter_addr_, &seen_counter)) {
      return false;
    }
    if (seen_counter != expected_counter) {
      *race = true;
      return false;
    }
  }
  return ok;
}

template <typename PointerT, typename SymSizeT>
bool JitDebugImpl<PointerT, SymSizeT>::ReadEntries(bool* race) {
  std::unordered_set<uint64_t> seen_entry_addr;
  std::vector<std::unique_ptr<CacheEntry>> new_entries;

  // We need to read the counter before we read desc.first_entry to ensure race safety.
  uint32_t counter;
  if (!memory_->Read32(counter_addr_, &counter)) {
    return false;
  }
  std::atomic_thread_fence(std::memory_order_acquire);

  // Read and verify the descriptor.
  JITDescriptor desc;
  if (!(memory_->ReadFully(descriptor_addr_, &desc, sizeof(desc)) && desc.version == 1 &&
        memcmp(desc.magic, kDescriptorMagic, 8) == 0)) {
    return false;
  }

  // Keep reading entries until we find one that we have seen before.
  // Entries are always added at the head of the list so this should work.
  JITCodeEntry entry;
  for (uint64_t entry_addr = desc.first_entry; entry_addr != 0; entry_addr = entry.next) {
    // Check for infinite loops in the lined list.
    if (!seen_entry_addr.emplace(entry_addr).second) {
      return false;
    }

    // Read the entry (while checking for data races).
    if (!SafeRead(entry_addr, &entry, sizeof(entry), race, counter)) {
      return false;
    }

    // Check whether we have reached an entry which has been already cached.
    if (entry.register_timestamp.value <= max_timestamp) {
      break;
    }

    // Make a copy of the in-memory ELF file (while checking for data races).
    std::unique_ptr<MemoryBuffer> buffer(new MemoryBuffer());
    buffer->Resize(entry.symfile_size.value);
    if (!SafeRead(entry.symfile_addr, buffer->GetPtr(0), buffer->Size(), race, counter)) {
      return false;
    }

    new_entries.push_back(std::unique_ptr<CacheEntry>(new CacheEntry{
        .timestamp_ = entry.register_timestamp.value, .buffer_ = std::move(buffer)}));
  }

  // Load and validate the ELF files (outside the critical loop).
  for (auto& it : new_entries) {
    it->elf_.reset(new Elf(it->buffer_.release()));
    it->elf_->Init(true);
    if (!it->elf_->valid()) {
      return false;
    }
    it->elf_->GetValidPcRange(&it->text_addr_, &it->text_size_);
  }

  // Save the results. We need to iterate in reverse (chronological) order.
  for (; !new_entries.empty(); new_entries.pop_back()) {
    std::unique_ptr<CacheEntry> it(std::move(new_entries.back()));
    max_timestamp = std::max(max_timestamp, it->timestamp_);

    // It is possible for ELF entry to have no executable code (e.g. type info).
    if (it->text_size_ != 0) {
      // Remove all old overlapping entries (presumably referring to GCed code).
      while (true) {
        // Upper bound returns the first entry for which (end > it->text_addr).
        auto ub = entries_.upper_bound(it->text_addr_);
        if (ub != entries_.end() && ub->second->text_addr_ < it->text_addr_ + it->text_size_) {
          entries_.erase(ub);
        } else {
          break;
        }
      }
      entries_.emplace(it->text_addr_ + it->text_size_, std::move(it));
    }
  }
  return true;
}

template <typename PointerT, typename SymSizeT>
bool JitDebugImpl<PointerT, SymSizeT>::ReadEntries(bool detect_races) {
  for (int i = 0; i < kMaxRaceRetries; i++) {
    bool race = false;  // Set to true if we detect data race.
    if (!ReadEntries(detect_races ? &race : nullptr)) {
      if (race) {
        continue;  // Try again (there was a data race).
      }
      return false;  // Proper failure (we could not read the data).
    }
    return true;  // Success.
  }
  return false;  // Too many retries.
}

}  // namespace unwindstack

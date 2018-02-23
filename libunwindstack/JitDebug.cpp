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

#include <DexFile.h>
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

// Wrapper around other memory object which protects us against data races.
// It will check seqlock after every read, and fail if the seqlock changed.
// This ensues that the read memory has not been partially modified.
struct JitDebugMemory : public Memory {
  size_t Read(uint64_t addr, void* dst, size_t size) override;

  Memory* parent_ = nullptr;
  uint64_t seqlock_addr_ = 0;
  uint32_t expected_seqlock_ = 0;
  bool failed_due_to_race_ = false;
};

template <typename Symfile>
struct JitCacheEntry {
  uint64_t pc_start_ = 0;
  uint64_t pc_end_ = 0;
  std::unique_ptr<Symfile> symfile_;

  bool Init(Maps* maps, JitDebugMemory* safe_memory, uint64_t addr, uint64_t size);
};

template <typename Symfile, typename PointerT, typename Uint64_T>
class JitDebugImpl : public JitDebug<Symfile> {
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
    uint32_t action_seqlock;
    uint64_t action_timestamp;
  };

  Symfile* Get(Maps* maps, uint64_t pc) override;

  void Init(Maps* maps);
  bool ReadNewEntries(Maps* maps, JitDebugMemory* safe_memory);

  bool initialized_ = false;
  uint64_t descriptor_addr_ = 0;

  // Cached entries sorted by the *end* address of the valid PC range.
  std::map<uint64_t, std::unique_ptr<JitCacheEntry<Symfile>>> entries_;

  // All entries at or before this timestamp have been already cached.
  uint64_t max_timestamp_ = 0;

  // The value of seqlock when we last completely updated the cached.
  uint32_t last_seqlock_ = ~0u;

  std::mutex lock_;
};

template <typename Symfile>
std::unique_ptr<JitDebug<Symfile>> JitDebug<Symfile>::Create(ArchEnum arch,
                                                             std::shared_ptr<Memory>& memory,
                                                             std::vector<std::string> search_libs) {
  typedef JitDebugImpl<Symfile, uint32_t, Uint64_P> JitDebugImpl32P;
  typedef JitDebugImpl<Symfile, uint32_t, Uint64_A> JitDebugImpl32A;
  typedef JitDebugImpl<Symfile, uint64_t, Uint64_A> JitDebugImpl64A;
  std::unique_ptr<JitDebug> jit;
  switch (arch) {
    case ARCH_X86:
      static_assert(sizeof(typename JitDebugImpl32P::JITCodeEntry) == 28, "layout");
      jit.reset(new JitDebugImpl32P());
      break;
    case ARCH_ARM:
    case ARCH_MIPS:
      static_assert(sizeof(typename JitDebugImpl32A::JITCodeEntry) == 32, "layout");
      jit.reset(new JitDebugImpl32A());
      break;
    case ARCH_ARM64:
    case ARCH_X86_64:
    case ARCH_MIPS64:
      static_assert(sizeof(typename JitDebugImpl64A::JITCodeEntry) == 40, "layout");
      jit.reset(new JitDebugImpl64A());
      break;
    default:
      abort();
  }
  jit->arch_ = arch;
  jit->memory_ = memory;
  jit->search_libs_ = std::move(search_libs);
  return jit;
}

size_t JitDebugMemory::Read(uint64_t addr, void* dst, size_t size) {
  bool ok = parent_->ReadFully(addr, dst, size);
  std::atomic_thread_fence(std::memory_order_acquire);
  uint32_t seen_seqlock;
  if (!parent_->Read32(seqlock_addr_, &seen_seqlock)) {
    return 0;
  }
  if (seen_seqlock != expected_seqlock_) {
    failed_due_to_race_ = true;
    return 0;
  }
  return ok ? size : 0;
}

template <typename Symfile, typename PointerT, typename Uint64_T>
Symfile* JitDebugImpl<Symfile, PointerT, Uint64_T>::Get(Maps* maps, uint64_t pc) {
  std::lock_guard<std::mutex> guard(lock_);
  if (!initialized_) {
    Init(maps);
  }

  // We might need to retry the whole read in the presence of data races.
  for (int i = 0; descriptor_addr_ != 0 && i < kMaxRaceRetries; i++) {
    // Read the seqlock (counter which is incremented before and after any modification).
    uint64_t seqlock_addr = descriptor_addr_ + offsetof(JITDescriptor, action_seqlock);
    uint32_t seqlock = 0;
    if (!this->memory_->Read32(seqlock_addr, &seqlock)) {
      return nullptr;  // Failed to read seqlock.
    }

    // Check if anything changed since the last time we checked.
    if (last_seqlock_ != seqlock) {
      // Create memory wrapper to allow us to read the entries safely even in a live process.
      JitDebugMemory safe_memory;
      safe_memory.parent_ = this->memory_.get();
      safe_memory.seqlock_addr_ = seqlock_addr;
      safe_memory.expected_seqlock_ = seqlock;
      std::atomic_thread_fence(std::memory_order_acquire);

      // Add all new entries to our cache.
      if (!ReadNewEntries(maps, &safe_memory)) {
        if (safe_memory.failed_due_to_race_) {
          continue;  // Try again (there was a data race).
        } else {
          return nullptr;  // Proper failure (we could not read the data).
        }
      }
      last_seqlock_ = seqlock;
    }

    // Upper bound returns the first entry for which (pc < entry.pc_end).
    auto ub = entries_.upper_bound(pc);
    if (ub != entries_.end() && ub->second->pc_start_ <= pc) {
      return ub->second->symfile_.get();
    }
    return nullptr;  // No symfile for the given pc.
  }
  return nullptr;  // Too many retries.
}

template <typename Symfile, typename PointerT, typename Uint64_T>
void JitDebugImpl<Symfile, PointerT, Uint64_T>::Init(Maps* maps) {
  if (initialized_) {
    return;
  }
  // Regardless of what happens below, consider the init finished.
  initialized_ = true;

  const std::string descriptor_name(Symfile::kJitDebugDescriptorName);
  for (MapInfo* info : *maps) {
    if (!(info->flags & PROT_EXEC) || !(info->flags & PROT_READ) || info->offset != 0) {
      continue;
    }

    if (!this->search_libs_.empty()) {
      bool found = false;
      const char* lib = basename(info->name.c_str());
      for (std::string& name : this->search_libs_) {
        if (strcmp(name.c_str(), lib) == 0) {
          found = true;
          break;
        }
      }
      if (!found) {
        continue;
      }
    }

    Elf* elf = info->GetElf(this->memory_, true);
    uint64_t descriptor_addr;
    if (elf->GetGlobalVariable(descriptor_name, &descriptor_addr)) {
      JITDescriptor desc;
      descriptor_addr += info->start;
      if (!this->memory_->ReadFully(descriptor_addr, &desc, sizeof(desc))) {
        continue;
      }
      descriptor_addr_ = descriptor_addr;
      if (desc.first_entry != 0) {
        break;  // Stop on the first descriptor that has any entries.
      }
    }
  }
}

// ELF specific code to load the file and its range of PCs.
template <>
bool JitCacheEntry<Elf>::Init(Maps*, JitDebugMemory* safe_memory, uint64_t addr, uint64_t size) {
  // Make a copy of the in-memory symbol file (while checking for data races).
  std::unique_ptr<MemoryBuffer> buffer(new MemoryBuffer());
  buffer->Resize(size);
  if (!safe_memory->ReadFully(addr, buffer->GetPtr(0), buffer->Size())) {
    return false;
  }

  // Load and validate the ELF file.
  symfile_.reset(new Elf(buffer.release()));
  symfile_->Init(true);
  if (!symfile_->valid()) {
    return false;
  }

  // Get the PC range (we allow empty range - e.g. type info has no executable code).
  symfile_->GetValidPcRange(&pc_start_, &pc_end_);
  return true;
}

// DEX specific code to load the file and its range of PCs.
template <>
bool JitCacheEntry<DexFile>::Init(Maps* maps, JitDebugMemory* safe_memory, uint64_t addr, uint64_t) {
  MapInfo* info = maps->Find(addr);
  if (info == nullptr) {
    return false;
  }
  DexFile* dex_file = DexFile::Create(addr, safe_memory, info);
  if (dex_file == nullptr) {
    return false;
  }
  symfile_.reset(dex_file);

  // Get the PC range.
  dex_file->GetValidPcRange(&pc_start_, &pc_end_);
  return true;
}

template <typename Symfile, typename PointerT, typename Uint64_T>
bool JitDebugImpl<Symfile, PointerT, Uint64_T>::ReadNewEntries(Maps* maps,
                                                               JitDebugMemory* safe_memory) {
  std::unordered_set<uint64_t> seen_entry_addr;
  std::vector<std::unique_ptr<JitCacheEntry<Symfile>>> entries;

  // Read and verify the descriptor (must be after we have read the initial seqlock).
  JITDescriptor desc;
  if (!(safe_memory->ReadFully(descriptor_addr_, &desc, sizeof(desc)) && desc.version == 1 &&
        memcmp(desc.magic, kDescriptorMagic, 8) == 0)) {
    return false;
  }

  // Keep reading entries until we find one that we have seen before.
  // Entries are always added at the head of the list so this should work.
  JITCodeEntry entry;
  uint64_t new_max_timestamp = max_timestamp_;
  for (uint64_t entry_addr = desc.first_entry; entry_addr != 0; entry_addr = entry.next) {
    // Check for infinite loops in the lined list.
    if (!seen_entry_addr.emplace(entry_addr).second) {
      return false;
    }

    // Read the entry (while checking for data races).
    if (!safe_memory->ReadFully(entry_addr, &entry, sizeof(entry))) {
      return false;
    }

    // Check whether we have reached an entry which has been already cached.
    if (entry.register_timestamp.value <= max_timestamp_) {
      break;
    }

    // Copy and load the symfile.
    entries.emplace_back(new JitCacheEntry<Symfile>());
    if (!entries.back()->Init(maps, safe_memory, entry.symfile_addr, entry.symfile_size.value)) {
      return false;
    }
    new_max_timestamp = std::max(new_max_timestamp, entry.register_timestamp.value);
  }

  // Save the results. We need to iterate in reverse (chronological) order.
  for (auto it = entries.rbegin(); it != entries.rend(); ++it) {
    std::unique_ptr<JitCacheEntry<Symfile>>& entry = *it;

    // It is possible for entry to have no executable code (e.g. type info).
    if (entry->pc_start_ == entry->pc_end_) {
      continue;
    }

    // Remove all old overlapping entries (presumably referring to old GCed code).
    while (true) {
      // Upper bound returns the first entry for which (entry->pc_start_ < ub->pc_end).
      auto ub = entries_.upper_bound(entry->pc_start_);
      if (ub != entries_.end() && ub->second->pc_start_ < entry->pc_end_) {
        entries_.erase(ub);
      } else {
        break;
      }
    }

    entries_.emplace(entry->pc_end_, std::move(entry));
  }
  max_timestamp_ = new_max_timestamp;
  return true;
}

template std::unique_ptr<JitDebug<Elf>> JitDebug<Elf>::Create(ArchEnum, std::shared_ptr<Memory>&,
                                                              std::vector<std::string>);
template std::unique_ptr<JitDebug<DexFile>> JitDebug<DexFile>::Create(ArchEnum,
                                                                      std::shared_ptr<Memory>&,
                                                                      std::vector<std::string>);
}  // namespace unwindstack

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
#include <deque>
#include <map>
#include <memory>
#include <unordered_set>
#include <vector>

#include <unwindstack/Elf.h>
#include <unwindstack/JitDebug.h>
#include <unwindstack/Maps.h>

#include "MemoryBuffer.h"
#include "MemoryRange.h"

#if !defined(NO_LIBDEXFILE_SUPPORT)
#include <DexFile.h>
#endif

// This implements the JIT Compilation Interface.
// See https://sourceware.org/gdb/onlinedocs/gdb/JIT-Interface.html

namespace unwindstack {

template <typename Symfile, typename PointerT, typename Uint64_T>
class JitDebugImpl : public JitDebug<Symfile>, public Global {
 public:
  static constexpr int kMaxRaceRetries = 16;
  static constexpr int kMaxHeadRetries = 16;

  struct JITCodeEntry {
    PointerT next;
    PointerT prev;
    PointerT symfile_addr;
    Uint64_T symfile_size;
    Uint64_T timestamp;
    uint32_t seqlock;
  };

  struct JITDescriptor {
    uint32_t version;
    uint32_t action_flag;
    PointerT relevant_entry;
    PointerT first_entry;
  };

  // This uniquely identifies entry in presence of concurrent modifications.
  // Each (address,seqlock) pair is unique for each newly created JIT entry.
  struct UID {
    uint64_t address;  // Address of JITCodeEntry in memory.
    uint32_t seqlock;  // If entry is modified, it's seqlock will be incremented.

    bool operator<(const UID& other) const {
      return address != other.address ? address < other.address : seqlock < other.seqlock;
    }
  };

  JitDebugImpl(ArchEnum arch, std::shared_ptr<Memory>& memory,
               std::vector<std::string>& search_libs)
      : Global(memory, search_libs) {
    SetArch(arch);
  }

  virtual void ProcessArch() {}

  // Callback for reading the global JIT descriptor.
  bool ReadVariableData(uint64_t addr) {
    JITDescriptor desc;
    if (!this->memory_->ReadFully(addr, &desc, sizeof(desc))) {
      return false;
    }
    if (desc.version != 1) {
      return false;
    }
    if (desc.first_entry == 0) {
      return false;  // There could be multiple descriptors. Ignore empty ones.
    }
    descriptor_addr_ = addr;
    return true;
  }

  // The main method for looking up symbols.
  Symfile* Get(Maps* maps, uint64_t pc) {
    std::lock_guard<std::mutex> guard(lock_);

    // Initialize - look for the global descriptor variable.
    if (!initialized_) {
      FindAndReadVariable(maps, GetDescriptorName(static_cast<Symfile*>(nullptr)));
      initialized_ = true;
    }
    if (descriptor_addr_ == 0) {
      return nullptr;
    }

    // Try to find the entry in already loaded symbol files.
    bool race = false;
    Symfile* symfile = GetCached(pc, &race);
    if (symfile != nullptr) {
      // return symfile;   // TODO: Re-enable
    }

    // Read all entries from the process to update the cache.
    // The linked list might be concurrently modified. We detect races and retry.
    for (int i = 0; i < kMaxRaceRetries; i++) {
      race = false;
      if (!ReadAllEntries(maps, &race)) {
        if (race) {
          continue;  // Retry due to concurrent modification of the linked list.
        }
        return nullptr;  // Failed to read entries.
      }
      race = false;
      if ((symfile = GetCached(pc, &race)) == nullptr) {
        if (race) {
          continue;  // Retry due to concurrent modification of the linked list.
        }
        printf("Failed to find JIT entry for %p\n", (void*)pc);
        return nullptr;  // Failed to find JIT entry.
      }
      return symfile;  // Success.
    }
    printf("Too many retries\n");
    return nullptr;  // Too many retries.
  }

  // Find symbol file in the already loaded cache.
  Symfile* GetCached(uint64_t pc, bool* race) {
    Symfile* result = nullptr;
    std::string result_name;
    for (auto& it : entries_) {
      UID uid = it.first;
      Symfile* symfile = it.second.get();
      // Check that the entry contains the PC in case there are overlapping entries.
      // This is might happen for native-code due to GC and for DEX due to data sharing.
      std::string method_name;
      uint64_t method_offset;
      // TODO: Check if in .text range.
      if (symfile->GetFunctionName(pc, &method_name, &method_offset)) {
        // Check that the entry has not been deleted.
        if (!CheckSeqlock(uid, race)) {
          return nullptr;
        }
        if (result != nullptr && result_name != method_name) {
          printf("Duplicate entry for %p (%s vs %s)\n",
              (void*)pc, result_name.c_str(), method_name.c_str());
          return nullptr;  // Conflicting results. Return nothing rather than wrong result.
        }
        result = symfile;  // Success.
        result_name = std::move(method_name);
      }
    }
    return result;
  }

  // Read the address and seqlock of entry from the next field of linked list.
  // This is non-trivial since they need to be consistent (as if we read both atomically).
  bool ReadNextField(uint64_t next_field_addr, UID* uid, bool* race) {
    PointerT address[2] { 0, 0 };
    uint32_t seqlock[2] { 0, 0 };
    // Read all data twice: address[0], seqlock[0], address[1], seqlock[1].
    for (int i = 0; i < 2; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      if (!(memory_->ReadFully(next_field_addr, &address[i], sizeof(address[i])))) {
        return false;
      }
      if (address[i] != 0) {
        std::atomic_thread_fence(std::memory_order_acquire);
        if (!memory_->ReadFully(address[i] + seqlock_offset_, &seqlock[i], sizeof(seqlock[i]))) {
          return false;
        }
      }
    }
    // Check that both reads returned identical values, and that the entry is live.
    if (address[0] != address[1] || seqlock[0] != seqlock[1] || (seqlock[0] & 1) == 1) {
      *race = true;
      return false;
    }
    // Since address[1] is sandwiched between two seqlock reads, we know that
    // at the time of address[1] read, the entry had the given seqlock value.
    *uid = UID { .address = address[1], .seqlock = seqlock[1] };
    return true;
  }

  // Check that the given entry has not been deleted (or replaced by new entry at same address).
  bool CheckSeqlock(UID uid, bool* race) {
    // This is required for memory synchronization if the we are working with local memory.
    // For other types of memory (e.g. remote) this is no-op and has no significant effect.
    std::atomic_thread_fence(std::memory_order_acquire);
    uint32_t seen_seqlock;
    if (!memory_->Read32(uid.address + seqlock_offset_, &seen_seqlock)) {
      return false;
    }
    if (seen_seqlock != uid.seqlock) {
      *race = true;
      return false;
    }
    return true;
  }

  // Read all JIT entries while assuming there might be concurrent modifications.
  // If there is a race, the method will fail and the caller should retry the call.
  bool ReadAllEntries(Maps* maps, bool* race) {
    // New entries might be added while we iterate over the linked list.
    // In particular, entry could be effectively moved from end to start
    // due to ART repacking algorithm, which groups smaller entries into big one.
    // Therefore keep reading the most recent entries until we reach fixed point.
    std::map<UID, std::shared_ptr<Symfile>> entries;
    for (size_t i = 0; i < kMaxHeadRetries; i++) {
      size_t num_entries = entries.size();
      if (!ReadNewEntries(maps, &entries, race)) {
        return false;
      }
      if (entries.size() == num_entries) {
        entries_.swap(entries);
        return true;
      }
    }
    return false;  // Max retries.
  }

  // Read recent JIT entries (head of linked list) until we find one that we have seen before.
  bool ReadNewEntries(Maps* maps, std::map<UID, std::shared_ptr<Symfile>>* entries, bool* race) {
    // Read the address of the head entry in the linked list.
    UID uid;
    if (!ReadNextField(descriptor_addr_ + offsetof(JITDescriptor, first_entry), &uid, race)) {
      return false;
    }

    // Follow the linked list.
    while (uid.address != 0) {
      // Check if we have reached previously loaded entry.
      if (entries->count(uid) != 0) {
        return true;
      }

      // Read the entry.
      JITCodeEntry data;
      if (!memory_->ReadFully(uid.address, &data, sizeof(data))) {
        return false;
      }

      // Check the seqlock to verify the symfile_addr and symfile_size.
      if (!CheckSeqlock(uid, race)) {
        return false;
      }

      // Copy and load the symfile.
      auto it = entries_.find(uid);
      if (it != entries_.end()) {
        // The symfile was already loaded - just copy the reference.
        entries->emplace(uid, it->second);
      } else if (data.symfile_addr != 0) {
        std::unique_ptr<Symfile> symfile;
        if (!Load(maps, uid, data.symfile_addr, data.symfile_size.value, &symfile, race)) {
          return false;
        }
        entries->emplace(uid, symfile.release());
      }

      // Go to next entry.
      UID next_uid;
      if (!ReadNextField(uid.address + offsetof(JITCodeEntry, next), &next_uid, race)) {
        return false;  // The next pointer was modified while we were reading it.
      }
      if (!CheckSeqlock(uid, race)) {
        return false;  // This entry was deleted before we moved to the next one.
      }
      uid = next_uid;
    }

    return true;
  }

  // The argument is unused - we only use it as specialization based on Symfile type.
  static const char* GetDescriptorName(Elf*) {
    return "__jit_debug_descriptor";
  }

  // Copy and load ELF file.
  bool Load(Maps*, UID uid, uint64_t sym_addr, uint64_t sym_size, std::unique_ptr<Elf>* symfile, bool* race) {
    // Make a copy of the in-memory symbol file (while checking for data races).
    std::unique_ptr<MemoryBuffer> buffer(new MemoryBuffer());
    buffer->Resize(sym_size);
    if (!memory_->ReadFully(sym_addr, buffer->GetPtr(0), buffer->Size())) {
      return false;
    }

    // Check the seqlock to verify the ELF data.
    if (!CheckSeqlock(uid, race)) {
      return false;
    }

    // Load and validate the ELF file.
    std::unique_ptr<Elf> elf(new Elf(buffer.release()));
    elf->Init();
    if (!elf->valid()) {
      return false;
    }

    *symfile = std::move(elf);
    return true;
  }

#if !defined(NO_LIBDEXFILE_SUPPORT)

  // The argument is unused - we only use it as specialization based on Symfile type.
  static const char* GetDescriptorName(DexFile*) {
    return "__dex_debug_descriptor";
  }

  // Copy and load DEX file.
  bool Load(Maps* maps, UID, uint64_t sym_addr, uint64_t, std::unique_ptr<DexFile>* symfile, bool*) {
    MapInfo* info = maps->Find(sym_addr);
    if (info == nullptr) {
      return false;
    }
    *symfile = DexFile::Create(sym_addr, memory_.get(), info);
    if (*symfile == nullptr) {
      return false;
    }
    return true;
  }

#endif

 private:
  bool initialized_ = false;
  uint64_t descriptor_addr_ = 0;  // Non-zero if we have found (non-empty) descriptor.
  uint32_t seqlock_offset_ = offsetof(JITCodeEntry, seqlock);
  std::map<UID, std::shared_ptr<Symfile>> entries_;  // Cached loaded entries.
  std::mutex lock_;
};

template <typename Symfile>
std::unique_ptr<JitDebug<Symfile>> JitDebug<Symfile>::Create(ArchEnum arch,
                                                             std::shared_ptr<Memory>& memory,
                                                             std::vector<std::string> search_libs) {
  // uint64_t values on x86 are not naturally aligned,
  // but uint64_t values on ARM are naturally aligned.
  struct Uint64_P { uint64_t value; } __attribute__((packed));
  struct Uint64_A { uint64_t value; } __attribute__((aligned(8)));

  switch (arch) {
    case ARCH_X86: {
      using Impl = JitDebugImpl<Symfile, uint32_t, Uint64_P>;
      static_assert(offsetof(typename Impl::JITCodeEntry, symfile_size) == 12, "layout");
      static_assert(offsetof(typename Impl::JITCodeEntry, seqlock) == 28, "layout");
      static_assert(sizeof(typename Impl::JITCodeEntry) == 32, "layout");
      static_assert(sizeof(typename Impl::JITDescriptor) == 16, "layout");
      return std::unique_ptr<JitDebug>(new Impl(arch, memory, search_libs));
      break;
    }
    case ARCH_ARM:
    case ARCH_MIPS: {
      using Impl = JitDebugImpl<Symfile, uint32_t, Uint64_A>;
      static_assert(offsetof(typename Impl::JITCodeEntry, symfile_size) == 16, "layout");
      static_assert(offsetof(typename Impl::JITCodeEntry, seqlock) == 32, "layout");
      static_assert(sizeof(typename Impl::JITCodeEntry) == 40, "layout");
      static_assert(sizeof(typename Impl::JITDescriptor) == 16, "layout");
      return std::unique_ptr<JitDebug>(new Impl(arch, memory, search_libs));
      break;
    }
    case ARCH_ARM64:
    case ARCH_X86_64:
    case ARCH_MIPS64: {
      using Impl = JitDebugImpl<Symfile, uint64_t, Uint64_A>;
      static_assert(offsetof(typename Impl::JITCodeEntry, symfile_size) == 24, "layout");
      static_assert(offsetof(typename Impl::JITCodeEntry, seqlock) == 40, "layout");
      static_assert(sizeof(typename Impl::JITCodeEntry) == 48, "layout");
      static_assert(sizeof(typename Impl::JITDescriptor) == 24, "layout");
      return std::unique_ptr<JitDebug>(new Impl(arch, memory, search_libs));
      break;
    }
    default:
      abort();
  }
}

template std::unique_ptr<JitDebug<Elf>> JitDebug<Elf>::Create(ArchEnum, std::shared_ptr<Memory>&,
                                                              std::vector<std::string>);
#if !defined(NO_LIBDEXFILE_SUPPORT)
template std::unique_ptr<JitDebug<DexFile>> JitDebug<DexFile>::Create(ArchEnum,
                                                                      std::shared_ptr<Memory>&,
                                                                      std::vector<std::string>);
#endif

}  // namespace unwindstack

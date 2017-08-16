/*
 * Copyright (C) 2014 The Android Open Source Project
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

#ifndef _BACKTRACE_BACKTRACE_MAP_H
#define _BACKTRACE_BACKTRACE_MAP_H

#include <stdint.h>
#include <sys/types.h>
#ifdef _WIN32
// MINGW does not define these constants.
#define PROT_NONE 0
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#else
#include <sys/mman.h>
#endif

#include <deque>
#include <iterator>
#include <string>
#include <vector>

// Special flag to indicate a map is in /dev/. However, a map in
// /dev/ashmem/... does not set this flag.
static constexpr int PROT_DEVICE_MAP = 0x8000;

struct backtrace_map_t {
  uintptr_t start = 0;
  uintptr_t end = 0;
  uintptr_t offset = 0;
  uintptr_t load_bias = 0;
  int flags = 0;
  std::string name;
};

class BacktraceMap {
public:
  // If uncached is true, then parse the current process map as of the call.
  // Passing a map created with uncached set to true to Backtrace::Create()
  // is unsupported.
  static BacktraceMap* Create(pid_t pid, bool uncached = false);
  // Same as above, but is compatible with the new unwinder.
  static BacktraceMap* CreateNew(pid_t pid, bool uncached = false);

  static BacktraceMap* Create(pid_t pid, const std::vector<backtrace_map_t>& maps);

  virtual ~BacktraceMap() = default;

  // Fill in the map data structure for the given address.
  virtual void FillIn(uintptr_t addr, backtrace_map_t* map) = 0;

  // The flags returned are the same flags as used by the mmap call.
  // The values are PROT_*.
  int GetFlags(uintptr_t pc) {
    backtrace_map_t map;
    FillIn(pc, &map);
    if (IsValid(map)) {
      return map.flags;
    }
    return PROT_NONE;
  }

  bool IsReadable(uintptr_t pc) { return GetFlags(pc) & PROT_READ; }
  bool IsWritable(uintptr_t pc) { return GetFlags(pc) & PROT_WRITE; }
  bool IsExecutable(uintptr_t pc) { return GetFlags(pc) & PROT_EXEC; }

  // In order to use the iterators on this object, a caller must
  // call the LockIterator and UnlockIterator function to guarantee
  // that the data does not change while it's being used.
  virtual void LockIterator() {}
  virtual void UnlockIterator() {}

  class Iterator : public std::iterator<std::bidirectional_iterator_tag, backtrace_map_t> {
   public:
    Iterator(BacktraceMap* map, size_t index) : map_(map), index_(index) {}

    Iterator& operator++() {
      index_++;
      return *this;
    }
    Iterator& operator++(int increment) {
      index_ += increment;
      return *this;
    }
    Iterator& operator--() {
      index_--;
      return *this;
    }
    Iterator& operator--(int decrement) {
      index_ -= decrement;
      return *this;
    }

    bool operator==(const Iterator& rhs) { return this->index_ == rhs.index_; }
    bool operator!=(const Iterator& rhs) { return this->index_ != rhs.index_; }

    backtrace_map_t operator*() { return map_->Get(index_); }

   private:
    BacktraceMap* map_;
    size_t index_;
  };

  Iterator begin() { return Iterator(this, 0); }
  Iterator end() { return Iterator(this, NumMaps()); }

  virtual backtrace_map_t Get(size_t index) = 0;
  virtual size_t NumMaps() = 0;
  virtual bool Build() = 0;

  static inline bool IsValid(const backtrace_map_t& map) { return map.end > 0; }

 protected:
  BacktraceMap(pid_t pid);

  pid_t pid_;
};

class ScopedBacktraceMapIteratorLock {
public:
  explicit ScopedBacktraceMapIteratorLock(BacktraceMap* map) : map_(map) {
    map->LockIterator();
  }

  ~ScopedBacktraceMapIteratorLock() {
    map_->UnlockIterator();
  }

private:
  BacktraceMap* map_;
};

#endif // _BACKTRACE_BACKTRACE_MAP_H

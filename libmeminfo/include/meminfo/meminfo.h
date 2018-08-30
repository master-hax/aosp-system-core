/*
 * Copyright (C) 2018 The Android Open Source Project
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

#pragma once

#include <sys/types.h>
#include <unistd.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <android-base/unique_fd.h>

#define _BITS(x, offset, bits) (((x) >> (offset)) & ((1LL << (bits)) - 1))
#define PAGE_PRESENT(x) (_BITS(x, 63, 1))
#define PAGE_SWAPPED(x) (_BITS(x, 62, 1))
#define PAGE_SHIFT(x) (_BITS(x, 55, 6))
#define PAGE_PFN(x) (_BITS(x, 0, 55))
#define PAGE_SWAP_OFFSET(x) (_BITS(x, 5, 50))
#define PAGE_SWAP_TYPE(x) (_BITS(x, 0, 5))

namespace android {
namespace meminfo {

struct MemUsage {
    uint64_t vss;
    uint64_t rss;
    uint64_t pss;
    uint64_t uss;

    uint64_t private_clean;
    uint64_t private_dirty;
    uint64_t shared_clean;
    uint64_t shared_dirty;

    MemUsage()
        : vss(0),
          rss(0),
          pss(0),
          uss(0),
          private_clean(0),
          private_dirty(0),
          shared_clean(0),
          shared_dirty(0) {}

    ~MemUsage() = default;

    void clear() {
        vss = rss = pss = uss = 0;
        private_clean = private_dirty = shared_clean = shared_dirty = 0;
    }

    MemUsage& operator+=(const MemUsage& mu) {
        vss += mu.vss;
        rss += mu.rss;
        pss += mu.pss;
        uss += mu.uss;

        private_clean += mu.private_clean;
        private_dirty += mu.private_dirty;

        shared_clean += mu.shared_clean;
        shared_dirty += mu.shared_dirty;

        return *this;
    }
};

struct Vma {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    uint16_t flags;
    std::string name;

    Vma(uint64_t s, uint64_t e, uint64_t off, uint16_t f, const char* n)
        : start(s), end(e), offset(off), flags(f), name(n) {}
    ~Vma() = default;

    struct MemUsage usage;
    struct MemUsage wss;
};

class PageInfo final {
  public:
    static inline uint64_t PageSize() {
        static uint64_t pagesize = sysconf(_SC_PAGE_SIZE);
        return pagesize;
    }

    static bool KernelHasPageIdle() {
        return (access("/sys/kernel/mm/page_idle/bitmap", R_OK | W_OK) == 0);
    }

    bool InitPageAcct(bool pageidle_enable = false);
    bool PageFlags(uint64_t pfn, uint64_t* flags);
    bool PageMapCount(uint64_t pfn, uint64_t* mapcount);

    int IsPageIdle(uint64_t pfn);

    // The only way to create PageInfo object
    static PageInfo& Instance() {
        static PageInfo instance;
        return instance;
    }

    ~PageInfo() = default;

  private:
    PageInfo() : kpagecount_fd_(-1), kpageflags_fd_(-1), pageidle_fd_(-1) {}
    int MarkPageIdle(uint64_t pfn) const;
    int GetPageIdle(uint64_t pfn) const;

    // Non-copyable & Non-movable
    PageInfo(const PageInfo&) = delete;
    PageInfo& operator=(const PageInfo&) = delete;
    PageInfo& operator=(PageInfo&&) = delete;
    PageInfo(PageInfo&&) = delete;

    ::android::base::unique_fd kpagecount_fd_;
    ::android::base::unique_fd kpageflags_fd_;
    ::android::base::unique_fd pageidle_fd_;
};

// per-process memory accounting
class ProcMemInfo final {
  public:
    ProcMemInfo(pid_t pid) : pid_(pid) {}

    const std::vector<std::unique_ptr<Vma>>& Maps();
    const MemUsage& Usage();
    const MemUsage& Wss();

    bool WssReset();
    ~ProcMemInfo() = default;

  private:
    bool ReadMaps(bool get_wss);
    bool ReadVmaStats(int pagemap_fd, struct Vma* vma, bool get_wss);

    pid_t pid_;

    std::vector<std::unique_ptr<Vma>> maps_;

    MemUsage usage_;
    MemUsage wss_;
};

// global memory accounting
class MemInfo final {
  public:
    static const std::vector<std::string> kDefaultMemInfoTags;

    MemInfo() = default;

    // Parse /proc/meminfo and read values needed
    bool ReadMemInfo(const std::string& path = "/proc/meminfo");
    bool ReadMemInfo(const std::vector<std::string>& tags,
                     const std::string& path = "/proc/meminfo");

    // getters
    uint64_t mem_total() { return mem_in_kb_["MemTotal:"]; }
    uint64_t mem_free() { return mem_in_kb_["MemFree:"]; }
    uint64_t buffers() { return mem_in_kb_["Buffers:"]; }
    uint64_t cached() { return mem_in_kb_["Cached:"]; }
    uint64_t shmem() { return mem_in_kb_["Shmem:"]; }
    uint64_t slab() { return mem_in_kb_["Slab:"]; }
    uint64_t slab_reclailmable() { return mem_in_kb_["SReclaimable:"]; }
    uint64_t slab_unreclaimable() { return mem_in_kb_["SUnreclaim:"]; }
    uint64_t swap() { return mem_in_kb_["SwapTotal:"]; }
    uint64_t free_swap() { return mem_in_kb_["SwapFree:"]; }
    uint64_t zram() { return mem_in_kb_["Zram:"]; }
    uint64_t mapped() { return mem_in_kb_["Mapped:"]; }
    uint64_t vmalloc_used() { return mem_in_kb_["VmallocUsed:"]; }
    uint64_t page_tables() { return mem_in_kb_["PageTables:"]; }
    uint64_t kernel_stack() { return mem_in_kb_["KernelStack:"]; }

  private:
    std::map<std::string, uint64_t> mem_in_kb_;
};

}  // namespace meminfo
}  // namespace android

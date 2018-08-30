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

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <android-base/unique_fd.h>

/* Map's PROT_READ, PROT_WRITE, PROT_EXEC flags */
#define PROCMAP_READ (1 << 0)
#define PROCMAP_WRITE (1 << 1)
#define PROCMAP_EXEC (1 << 2)
#define PROCMAP_PERMS (PROCMAP_READ | PROCMAP_WRITE | PROCMAP_EXEC)

/* Map's MAP_SHARED, MAP_PRIVATE flags */
#define PROCMAP_PRIVATE (1 << 3)
#define PROCMAP_SHARED (1 << 4)

#define _BITS(x, offset, bits) (((x) >> (offset)) & ((1LL << (bits)) - 1))
#define PAGE_PRESENT(x) (_BITS(x, 63, 1))
#define PAGE_SWAPPED(x) (_BITS(x, 62, 1))
#define PAGE_SHIFT(x) (_BITS(x, 55, 6))
#define PAGE_PFN(x) (_BITS(x, 0, 55))
#define PAGE_SWAP_OFFSET(x) (_BITS(x, 5, 50))
#define PAGE_SWAP_TYPE(x) (_BITS(x, 0, 5))

namespace android {
namespace meminfo {

class MemInfo final {
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

    // The only way to create MemInfo object
    static MemInfo& Instance() {
        static MemInfo instance;
        return instance;
    }

    ~MemInfo() = default;

  private:
    MemInfo() : kpagecount_fd_(-1), kpageflags_fd_(-1), pageidle_fd_(-1) {}
    int MarkPageIdle(uint64_t pfn) const;
    int GetPageIdle(uint64_t pfn) const;

    // Non-copyable & Non-movable
    MemInfo(const MemInfo&) = delete;
    MemInfo& operator=(const MemInfo&) = delete;
    MemInfo& operator=(MemInfo&&) = delete;
    MemInfo(MemInfo&&) = delete;

    ::android::base::unique_fd kpagecount_fd_;
    ::android::base::unique_fd kpageflags_fd_;
    ::android::base::unique_fd pageidle_fd_;
};

class ProcMemInfo final {
  public:
    struct ProcMap {
        uint64_t start;
        uint64_t end;
        uint64_t offset;
        uint32_t flags;
        std::string name;

        uint64_t vss;
        uint64_t rss;
        uint64_t pss;
        uint64_t uss;

        std::vector<uint64_t> page_frames;
        std::vector<uint64_t> page_flags;
        std::vector<uint64_t> page_counts;
    };

    ProcMemInfo(pid_t pid);
    const std::vector<std::unique_ptr<ProcMap>>& Maps() const { return maps_; }

    uint64_t Vss() const { return vss_; }

    uint64_t Rss() const { return rss_; }

    uint64_t Pss() const { return pss_; }

    uint64_t Uss() const { return uss_; }

    ~ProcMemInfo() = default;

  private:
    bool ReadMapInfo(int pagemap_fd, ProcMap* map);

    pid_t pid_;

    ::android::base::unique_fd pagemap_fd_;

    uint32_t nr_maps_;
    std::vector<std::unique_ptr<ProcMap>> maps_;

    uint64_t vss_;
    uint64_t rss_;
    uint64_t pss_;
    uint64_t uss_;
};

bool ReadProcMemInfo(std::unordered_map<std::string, uint64_t>* proc_meminfo,
                     const std::string& path = "/proc/meminfo");

}  // namespace meminfo
}  // namespace android

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

#define LOG_TAG "libmeminfo"

#include "meminfo/meminfo.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/kernel-page-flags.h>
#include <stdio.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <utility>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <procinfo/process_map.h>

namespace android {
namespace meminfo {

const std::vector<std::unique_ptr<Vma>>& ProcMemInfo::Maps() {
    if (!ReadMaps(false)) {
        LOG(ERROR) << "Failed to read maps for Process " << pid_;
    }
    return maps_;
}

const MemUsage& ProcMemInfo::Usage() {
    if (!ReadMaps(false)) {
        LOG(ERROR) << "Failed to read usage for process " << pid_;
    }

    return usage_;
}

const MemUsage& ProcMemInfo::Wss() {
    if (!ReadMaps(true)) {
        LOG(ERROR) << "failed to read working set for process " << pid_;
    }

    return wss_;
}

bool ProcMemInfo::WssReset() {
    std::string clear_refs = ::android::base::StringPrintf("/proc/%d/clear_refs", pid_);
    ::android::base::unique_fd clear_refs_fd(
            TEMP_FAILURE_RETRY(open(clear_refs.c_str(), O_WRONLY | O_CLOEXEC)));
    if (clear_refs_fd < 0) {
        PLOG(ERROR) << "Failed to open " << clear_refs;
        return false;
    }

    if (!::android::base::WriteStringToFd("1\n", clear_refs_fd)) {
        PLOG(ERROR) << "Failed to write to " << clear_refs;
        return false;
    }

    return true;
}

bool ProcMemInfo::ReadMaps(bool get_wss) {
    // This ensures the /proc/pid/maps is only ever read successfully once per-object.
    if (!maps_.empty()) return true;

    // parse and read /proc/<pid>/maps
    std::string maps_file = "/proc/" + std::to_string(pid_) + "/maps";
    if (!::android::procinfo::ReadMapFile(
                maps_file, [&](uint64_t start, uint64_t end, uint16_t flags, uint64_t pgoff,
                               const char* name) {
                    maps_.emplace_back(std::make_unique<Vma>(start, end, pgoff, flags, name));
                })) {
        LOG(ERROR) << "Failed to parse " << maps_file;
        maps_.clear();
        return false;
    }

    std::string pagemap_file = ::android::base::StringPrintf("/proc/%d/pagemap", pid_);
    ::android::base::unique_fd pagemap_fd(
            TEMP_FAILURE_RETRY(open(pagemap_file.c_str(), O_RDONLY | O_CLOEXEC)));
    if (pagemap_fd < 0) {
        PLOG(ERROR) << "Failed to open " << pagemap_file;
        return false;
    }

    for (auto& vma : maps_) {
        if (!ReadVmaStats(pagemap_fd.get(), vma.get(), get_wss)) {
            LOG(ERROR) << "Failed to read page map for vma " << vma->name << "[" << vma->start
                       << "-" << vma->end << "]";
            maps_.clear();
            return false;
        }
        if (get_wss) {
            wss_ += vma->wss;
        } else {
            usage_ += vma->usage;
        }
    }

    return true;
}

bool ProcMemInfo::ReadVmaStats(int pagemap_fd, struct Vma* vma, bool get_wss) {
    PageInfo& pinfo = PageInfo::Instance();
    uint64_t pagesize = PageInfo::PageSize();
    uint64_t num_pages = (vma->end - vma->start) / pagesize;

    std::unique_ptr<uint64_t[]> pg_frames(new uint64_t[num_pages]);
    uint64_t first = vma->start / pagesize;
    if (pread64(pagemap_fd, pg_frames.get(), num_pages * sizeof(uint64_t),
                first * sizeof(uint64_t)) < 0) {
        PLOG(ERROR) << "Failed to read page frames from page map for pid: " << pid_;
        return false;
    }

    std::unique_ptr<uint64_t[]> pg_flags(new uint64_t[num_pages]);
    std::unique_ptr<uint64_t[]> pg_counts(new uint64_t[num_pages]);
    for (uint64_t i = 0; i < num_pages; ++i) {
        if (!get_wss) {
            vma->usage.vss += pagesize;
        }
        uint64_t p = pg_frames[i];
        if (!PAGE_PRESENT(p) && !PAGE_SWAPPED(p)) continue;

        if (PAGE_SWAPPED(p)) {
            // TODO: do what's needed for swapped pages
            continue;
        }

        uint64_t page_frame = PAGE_PFN(p);
        if (!pinfo.PageFlags(page_frame, &pg_flags[i])) {
            LOG(ERROR) << "Failed to get page flags for " << page_frame << " in process " << pid_;
            return false;
        }

        if (!pinfo.PageMapCount(page_frame, &pg_counts[i])) {
            LOG(ERROR) << "Failed to get page count for " << page_frame << " in process " << pid_;
            return false;
        }

        // Page was unmapped between the presence check at the beginning of the loop and here.
        if (pg_counts[i] == 0) {
            pg_frames[i] = 0;
            pg_flags[i] = 0;
            continue;
        }

        bool is_dirty = !!(pg_flags[i] & (1 << KPF_DIRTY));
        bool is_private = (pg_counts[i] == 1);
        // Working set
        if (get_wss) {
            bool is_referenced = !!(pg_flags[i] & (1 << KPF_REFERENCED));
            if (!is_referenced) {
                continue;
            }
            // This effectively makes vss = rss for the working set is requested.
            // The libpagemap implementation returns vss > rss for
            // working set, which doesn't make sense.
            vma->wss.vss += pagesize;
            vma->wss.rss += pagesize;
            vma->wss.uss += is_private ? pagesize : 0;
            vma->wss.pss += pagesize / pg_counts[i];
            if (is_private) {
                vma->wss.private_dirty += is_dirty ? pagesize : 0;
                vma->wss.private_clean += is_dirty ? 0 : pagesize;
            } else {
                vma->wss.shared_dirty += is_dirty ? pagesize : 0;
                vma->wss.shared_clean += is_dirty ? 0 : pagesize;
            }
        } else {
            vma->usage.rss += pagesize;
            vma->usage.uss += is_private ? pagesize : 0;
            vma->usage.pss += pagesize / pg_counts[i];
            if (is_private) {
                vma->usage.private_dirty += is_dirty ? pagesize : 0;
                vma->usage.private_clean += is_dirty ? 0 : pagesize;
            } else {
                vma->usage.shared_dirty += is_dirty ? pagesize : 0;
                vma->usage.shared_clean += is_dirty ? 0 : pagesize;
            }
        }
    }

    return true;
}

}  // namespace meminfo
}  // namespace android

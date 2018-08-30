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
#include <stdio.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <utility>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>

namespace android {
namespace meminfo {

ProcMemInfo::ProcMemInfo(pid_t pid)
    : pid_(pid), pagemap_fd_(-1), nr_maps_(0), vss_(0), rss_(0), pss_(0), uss_(0) {
    std::string pagemap_file = ::android::base::StringPrintf("/proc/%d/pagemap", pid);
    ::android::base::unique_fd fd(
            TEMP_FAILURE_RETRY(open(pagemap_file.c_str(), O_RDONLY | O_CLOEXEC)));
    if (fd < 0) {
        PLOG(ERROR) << "Failed to open " << pagemap_file;
        return;
    }

    std::string maps_file = ::android::base::StringPrintf("/proc/%d/maps", pid);
    std::ifstream ifs{maps_file.c_str()};
    if (!ifs.is_open()) {
        PLOG(ERROR) << "Failed to open " << maps_file;
        return;
    }

    for (std::string line; std::getline(ifs, line);) {
        // Parse each line and add to the maps_
        // Each line looks as follows, except the 'name' of the region may
        // be empty
        //  7f90d0e000-7f90d0f000 r--p 00000000 00:00 0 [anon:linker_alloc]
        std::unique_ptr<ProcMemInfo::ProcMap> map(new ProcMap());
        if (!map) {
            LOG(ERROR) << "Failed to allocate ProcMap";
            return;
        }
        int name_pos;
        char perms[5];
        std::sscanf(line.c_str(), "%" SCNx64 "-%" SCNx64 " %4s %" SCNx64 " %*s %*d %n", &map->start,
                    &map->end, perms, &map->offset, &name_pos);
        if (name_pos < line.size()) {
            map->name = line.substr(name_pos);
        }

        if (perms[0] == 'r') map->flags |= PROCMAP_READ;
        if (perms[1] == 'w') map->flags |= PROCMAP_WRITE;
        if (perms[2] == 'x') map->flags |= PROCMAP_EXEC;
        if (perms[3] == 's')
            map->flags |= PROCMAP_SHARED;
        else if (perms[3] == 'p')
            map->flags |= PROCMAP_PRIVATE;
        else
            LOG(FATAL) << "Unknown permissions in map: " << line;

        if (!ReadMapInfo(fd.get(), map.get())) {
            LOG(ERROR) << "Failed to read page map for map " << map->name << "[" << map->start
                       << "-" << map->end << "]";
            return;
        }

        // Add the map to our list
        vss_ += map->vss;
        rss_ += map->rss;
        pss_ += map->pss;
        uss_ += map->uss;
        maps_.push_back(std::move(map));
    }

    pagemap_fd_ = std::move(fd);
    nr_maps_ = maps_.size();
}

bool ProcMemInfo::ReadMapInfo(int pagemap_fd, ProcMemInfo::ProcMap* map) {
    MemInfo& minfo = MemInfo::Instance();
    uint64_t pagesize = MemInfo::PageSize();
    uint64_t num_pages = (map->end - map->start) / pagesize;

    std::unique_ptr<uint64_t[]> pg_frames(new uint64_t[num_pages]);
    std::vector<uint64_t> pg_flags(num_pages, 0);
    std::vector<uint64_t> pg_counts(num_pages, 0);

    uint64_t first = map->start / pagesize;
    if (pread64(pagemap_fd, pg_frames.get(), num_pages * sizeof(uint64_t),
                first * sizeof(uint64_t)) < 0) {
        PLOG(ERROR) << "Failed to read page frames from page map for pid: " << pid_;
        return false;
    }

    uint64_t temp, page_frame;
    uint64_t vss = 0, rss = 0, uss = 0, pss = 0;
    for (uint64_t i = 0; i < num_pages; ++i) {
        vss += pagesize;

        uint64_t p = pg_frames[i];
        if (!PAGE_PRESENT(p) && !PAGE_SWAPPED(p)) continue;

        if (PAGE_SWAPPED(p)) {
            // TODO: do what's needed for swapped pages
            continue;
        }

        page_frame = PAGE_PFN(p);
        if (!minfo.PageFlags(page_frame, &temp)) {
            LOG(ERROR) << "Failed to get page flags for " << page_frame << " in process " << pid_;
            return false;
        }
        pg_flags[i] = temp;

        if (!minfo.PageMapCount(page_frame, &temp)) {
            LOG(ERROR) << "Failed to get page count for " << page_frame << " in process " << pid_;
            return false;
        }
        pg_counts[i] = temp;

        rss += pg_counts[i] >= 1 ? pagesize : 0;
        uss += pg_counts[i] == 1 ? pagesize : 0;
        pss += (pg_counts[i] >= 1) ? (pagesize / pg_counts[i]) : 0;
    }

    map->page_frames.reserve(num_pages);
    map->page_frames.assign(pg_frames.get(), pg_frames.get() + num_pages);
    map->page_flags = std::move(pg_flags);
    map->page_counts = std::move(pg_counts);

    map->vss = vss;
    map->rss = rss;
    map->pss = pss;
    map->uss = uss;

    return true;
}

}  // namespace meminfo
}  // namespace android

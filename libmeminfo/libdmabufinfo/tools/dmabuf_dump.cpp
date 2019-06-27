/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <android-base/stringprintf.h>
#include <dmabufinfo/dmabufinfo.h>

using DmaBuffer = ::android::dmabufinfo::DmaBuffer;

class DmaBufferComparator {
  public:
    bool operator()(const DmaBuffer& lhs, const DmaBuffer& rhs) const {
        if (lhs.inode() == rhs.inode()) return false;

        if (lhs.size() < rhs.size()) {
            return true;
        }
        return false;
    }
};

[[noreturn]] static void usage(int exit_status) {
    fprintf(stderr,
            "Usage: %s [-ah] [PID] \n"
            "-a\t show all dma buffers (ion) in big table, [buffer x process] grid \n"
            "-h\t show this help\n"
            "  \t If PID is supplied, the dmabuf information for that process is shown.\n",
            getprogname());

    exit(exit_status);
}

static std::string GetProcessComm(const pid_t pid) {
    std::string pid_path = android::base::StringPrintf("/proc/%d/comm", pid);
    std::ifstream in{pid_path};
    if (!in) return std::string("N/A");
    std::string line;
    std::getline(in, line);
    if (!in) return std::string("N/A");
    return line;
}

static void PrintDmaBufTable(const std::vector<DmaBuffer>& bufs) {
    if (bufs.empty()) {
        printf("dmabuf info not found ¯\\_(ツ)_/¯\n");
        return;
    }

    // Find all unique pids in the input vector, create a set
    std::set<pid_t> pid_set;
    for (auto& buf : bufs) {
        pid_set.insert(buf.pids().begin(), buf.pids().end());
    }

    // Format the header string spaced and separated with '|'
    printf("    Dmabuf Inode |            Size |      Ref Counts |");
    for (auto pid : pid_set) {
        printf("%16s:%-5d |", GetProcessComm(pid).c_str(), pid);
    }
    printf("\n");

    // holds per-process dmabuf size in kB
    std::map<pid_t, uint64_t> per_pid_size = {};
    uint64_t dmabuf_total_size = 0;

    // Iterate through all dmabufs and collect per-process sizes, refs
    for (auto& buf : bufs) {
        printf("%16ju |%13" PRIu64 " kB |%16" PRIu64 " |", static_cast<uintmax_t>(buf.inode()),
               buf.size() / 1024, buf.total_refs());
        // Iterate through each process to find out per-process references for each buffer,
        // gather total size used by each process etc.
        for (pid_t pid : pid_set) {
            int pid_refs = 0;
            if (buf.fdrefs().count(pid) == 1) {
                // Get the total number of ref counts the process is holding
                // on this buffer. We don't differentiate between mmap or fd.
                pid_refs += buf.fdrefs().at(pid);
                if (buf.maprefs().count(pid) == 1) {
                    pid_refs += buf.maprefs().at(pid);
                }
            }

            if (pid_refs) {
                // Add up the per-pid total size. Note that if a buffer is mapped
                // in 2 different processes, the size will be shown as mapped or opened
                // in both processes. This is intended for visibility.
                //
                // If one wants to get the total *unique* dma buffers, they can simply
                // sum the size of all dma bufs shown by the tool
                per_pid_size[pid] += buf.size() / 1024;
                printf("%17d refs |", pid_refs);
            } else {
                printf("%22s |", "--");
            }
        }
        dmabuf_total_size += buf.size() / 1024;
        printf("\n");
    }

    printf("------------------------------------\n");
    printf("%-16s  %13" PRIu64 " kB |%16s |", "TOTALS", dmabuf_total_size, "n/a");
    for (auto pid : pid_set) {
        printf("%19" PRIu64 " kB |", per_pid_size[pid]);
    }
    printf("\n");

    return;
}

static void PrintDmaBufPerProcess(const std::vector<DmaBuffer>& bufs) {
    if (bufs.empty()) {
        printf("dmabuf info not found ¯\\_(ツ)_/¯\n");
        return;
    }

    // Create a reverse map from pid to dmabufs
    std::unordered_map<pid_t, std::set<DmaBuffer, DmaBufferComparator>> pid_to_dmabufs = {};
    for (auto& buf : bufs) {
        for (auto pid : buf.pids()) {
            pid_to_dmabufs[pid].insert(buf);
        }
    }

    uint64_t total_rss = 0, total_pss = 0;
    for (auto it = pid_to_dmabufs.begin(); it != pid_to_dmabufs.end(); ++it) {
        pid_t pid = it->first;
        uint64_t pss = 0;
        uint64_t rss = 0;

        printf("%16s:%-5d\n", GetProcessComm(pid).c_str(), pid);
        printf("%22s %16s %16s %16s\n", "Name", "Rss", "Pss", "nr_procs");
        std::set<DmaBuffer, DmaBufferComparator>& dmabufs = it->second;
        for (auto& buf : dmabufs) {
            printf("%22s %13" PRIu64 " kB %13" PRIu64 " kB %16zu\n",
                   buf.name().empty() ? "<unknown>" : buf.name().c_str(), buf.size() / 1024,
                   buf.Pss() / 1024, buf.pids().size());
            rss += buf.size();
            pss += buf.Pss();
        }
        printf("%22s %13" PRIu64 " kB %13" PRIu64 " kB %16s\n", "PROCESS TOTAL", rss / 1024,
               pss / 1024, "");
        printf("----------------------\n");
        total_rss += rss;
        total_pss += pss;
    }
    printf("%22s %13" PRIu64 " kB %13" PRIu64 " kB %16s\n", "TOTAL", total_rss / 1024,
           total_pss / 1024, "");
}

static bool ReadDmaBufs(std::vector<DmaBuffer>* bufs) {
    bufs->clear();

    if (!ReadDmaBufInfo(bufs)) {
        fprintf(stderr, "debugfs entry for dmabuf not available, skipping\n");
        return false;
    }

    std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir("/proc"), closedir);
    if (!dir) {
        fprintf(stderr, "Failed to open /proc directory\n");
        bufs->clear();
        return false;
    }

    struct dirent* dent;
    while ((dent = readdir(dir.get()))) {
        if (dent->d_type != DT_DIR) continue;

        int pid;
        int matched = sscanf(dent->d_name, "%d", &pid);
        if (matched != 1) {
            continue;
        }

        if (!AppendDmaBufInfo(pid, bufs)) {
            fprintf(stderr, "Unable to read dmabuf info for pid %d\n", pid);
            bufs->clear();
            return false;
        }
    }

    return true;
}

int main(int argc, char* argv[]) {
    struct option longopts[] = {{"all", no_argument, nullptr, 'a'},
                                {"help", no_argument, nullptr, 'h'},
                                {0, 0, nullptr, 0}};

    int opt;
    bool show_table = false;
    while ((opt = getopt_long(argc, argv, "ah", longopts, nullptr)) != -1) {
        switch (opt) {
            case 'a':
                show_table = true;
                break;
            case 'h':
                usage(0);
                break;
            default:
                usage(EXIT_FAILURE);
        }
    }

    pid_t pid = -1;
    if (optind < argc) {
        pid = atoi(argv[optind]);
        if (pid <= 0) {
            fprintf(stderr, "Invalid process id %s\n", argv[optind]);
            usage(EXIT_FAILURE);
        }
    }

    std::vector<DmaBuffer> bufs;
    if (pid != -1) {
        if (!ReadDmaBufInfo(pid, &bufs)) {
            fprintf(stderr, "Unable to read dmabuf info for %d\n", pid);
            exit(EXIT_FAILURE);
        }
    } else {
        if (!ReadDmaBufs(&bufs)) exit(EXIT_FAILURE);
    }

    // Show the old dmabuf table, inode x process
    if (show_table) {
        PrintDmaBufTable(bufs);
        return 0;
    }

    PrintDmaBufPerProcess(bufs);

    return 0;
}

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

#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <memory>
#include <vector>

#include <android-base/parseint.h>
#include <android-base/stringprintf.h>

#include <meminfo/procmeminfo.h>

static void usage(const char* myname) {
    std::cerr << "Usage: " << myname << " [ -W ] [ -v | -r | -p | -u | -s | -h ]" << std::endl
              << "    -v  Sort by VSS." << std::endl
              << "    -r  Sort by RSS." << std::endl
              << "    -p  Sort by PSS." << std::endl
              << "    -u  Sort by USS." << std::endl
              << "    -s  Sort by swap." << std::endl
              << "        (Default sort order is PSS.)" << std::endl
              << "    -R  Reverse sort order (default is descending)." << std::endl
              << "    -c  Only show cached (storage backed) pages" << std::endl
              << "    -C  Only show non-cached (ram/swap backed) pages" << std::endl
              << "    -k  Only show pages collapsed by KSM" << std::endl
              << "    -w  Display statistics for working set only." << std::endl
              << "    -W  Reset working set of all processes." << std::endl
              << "    -o  Show and sort by oom score against lowmemorykiller thresholds."
              << std::endl
              << "    -h  Display this help screen." << std::endl;
}

bool GetAllPids(std::vector<pid_t>* pids) {
    pids->clear();
    std::unique_ptr<DIR, int(*)(DIR*)> procdir(opendir("/proc"), closedir);
    if (!procdir) return false;

    struct dirent* dir;
    pid_t pid;
    while ((dir = readdir(procdir))) {
        if (!::android::base::ParseUint(dir->d_name, &pid)) continue;
        pids->emplace_back(pid);
    }

    return true;
}

struct ProcessRecord {
    ::android::meminfo::ProcMemInfo* proc;
    int32_t oomadj;
    pid_t pid;
    
    ProcessRecord() = default;
    ~ProcessRecord() = default;

    bool Create(pid_t p) {
        pid = p;

        proc = new ::android::meminfo::ProcMemInfo(pid);
        if (proc == nullptr) {
            std::cerr << "Failed to create ProcMemInfo for " << pid << std::endl;
            return false;
        }

        std::string fname = ::android::base::StringPrintf("/proc/%d/oom_score_adj", pid);
        std::string oomadj_str;

        if (!::android::base::ReadFileToString(fname, &oomadj_str)) {
            std::cerr << "Failed to read " << fname;
            return false;
        }

        if (!::android::base::PareInt(oomadj_str, &oomadj)) {
            std::cerr << "Failed to parse int " << oomadj_str;
            return false;
        }

        return true;
    }

    bool CountSwapOffsets(uint16_t* swap_offset_array, uint32_t size) {
        std::vector<uint16_t>& swp_offs = proc->SwapOffsets();
        for (auto off : swp_offs) {
            if (off >= size) {
                std::cerr << "swap offset " << off << " is out of bounds for process " << pid << std::endl;
                return false;
            }

            if (swap_offset_array[off] == USHRT_MAX) {
                std::cerr << "swap offset " << off << " ref count overflow in process " << pid << std::endl;
                return false;
            }

            swap_offset_array[off]++;
        }
    }
};

static void show_header(bool show_wss, bool show_oomadj, bool has_swap, bool has_zram) {
    std::string header = ::android::base::StringPrintf("%5s  ", "PID");
    if (show_oomadj) {
        header += ::android::base::StringPrintf("%5s  ", "oom");
    }

    if (show_wss) {
        header += ::android::base::StringPrintf("%7s  %7s  %7s  ", "WRss", "WPss", "WUss");
        if (has_swap) {
            header += ::android::base::StringPrintf("%7s  %7s  %7s  ", "WSwap", "WPSwap", "WUSwap");
            if (has_zram) {
                header += ::android::base::StringPrintf("%7s  ", "WZSwap");
            }
        }
    } else {
        header += ::android::base::StringPrintf("%8s  %7s  %7s  %7s  ", "Vss", "Rss", "Pss", "Uss");
        if (has_swap) {
            header += ::android::base::StringPrintf("%7s  %7s  %7s  ", "Swap", "PSwap", "USwap");
            if (has_zram) {
                header += ::android::base::StringPrintf("%7s  ", "ZSwap");
            }
        }
    }
}

int main(int argc, char* argv[]) {
    bool get_wss = false;
    bool show_oomadj = false;
    int opt;

    while ((opt = getopt(argc, argv, "cChkoprRsuvwW")) != -1) {
        switch (opt) {
            case 'c':
                break;
            case 'C':
                break;
            case 'h':
                usage(argv[0]);
                return 0;
                break;
            case 'k':
                break;
            case 'o':
                break;
            case 'p':
                break;
            case 'r':
                break;
            case 'R':
                break;
            case 's':
                break;
            case 'u':
                break;
            case 'v':
                break;
            case 'w':
                get_wss = true;
                break;
            case 'W':
                break;
            default:
                abort();
        }
    }

    ::android::meminfo::SysMemInfo smi;
    if (!smi.ReadMemInfo()) {
        std::cerr << "Failed to get system memory info" << std::endl;
        exit(EXIT_FAILURE);
    }

    uint64_t swap_total = smi.mem_swap_kb() * 1024;
    bool has_swap = swap_total > 0;
    bool has_zram = smi.mem_zram_kb() > 0;

    // Allocate the swap array
    std::unique_ptr<uint16_t, decltype(&free)> swap_offset_array(
            calloc(swap_total / getpagesize(), sizeof(uint16_t)), free);

    std::vector<pid_t> pids;
    if (!GetAllPids(&pids)) {
        std::cerr << "Failed to read all pids from the system" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::vector<Processrecord> processes;
    for (auto each_pid : pids) {
        ProcessRecord prec;
        if (!prec.Create(each_pid)) {
            std::cerr << "Failed to create process record for " << pid;
            continue;
        }

        if (!proc.CountSwapOffsets(swap_offset_array.get(), swap_total / getpagesize())) {
            std::cerr << "Failed to count swap offsets for process " << pid;
            continue;
        }

        processes.emplace_back(std::move(prec));
    }

    // Remove process with vss zero
    processes.erase(std::remove_if(processes.begin(), processes.end(), [] (auto prec) {
                return prec.proc.Usage().vss == 0;
                }));

    show_header(get_wss, show_oomadj, has_swap, has_zram);

    return 0;
}

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
#include <inttypes.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <memory>
#include <sstream>
#include <vector>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include <meminfo/procmeminfo.h>
#include <meminfo/sysmeminfo.h>

struct ProcessRecord {
  public:
    ProcessRecord()
        : pid_(-1),
          procmem_(nullptr),
          oomadj_(1000),
          cmdline_(""),
          proportional_swap_(0),
          unique_swap_(0),
          zswap_(0) {}
    ~ProcessRecord() = default;

    bool Create(pid_t p) {
        pid_ = p;

        std::unique_ptr<::android::meminfo::ProcMemInfo> procmem =
                std::make_unique<::android::meminfo::ProcMemInfo>(pid_);
        if (procmem == nullptr) {
            std::cerr << "Failed to create ProcMemInfo for: " << pid_ << std::endl;
            return false;
        }

        std::string fname = ::android::base::StringPrintf("/proc/%d/oom_score_adj", pid_);
        std::string oomadj_str;

        if (!::android::base::ReadFileToString(fname, &oomadj_str)) {
            std::cerr << "Failed to read oomadj from: " << fname << std::endl;
            return false;
        }
        // android::base::ParseInt does not like trailing '\n' that all the proc files
        // have. So, stick with atoi() for now.
        oomadj_ = atoi(oomadj_str.c_str());

        fname = ::android::base::StringPrintf("/proc/%d/cmdline", pid_);
        std::string cmdline;
        if (!::android::base::ReadFileToString(fname, &cmdline)) {
            std::cerr << "Failed to read cmdline from: " << fname << std::endl;
            cmdline_ = "<unknown>";
        }
        // We deliberately don't read the proc/<pid>cmdline file directly into 'cmdline_'
        // because of some processes showing up cmdlines that end with "0x00 0x0A 0x00"
        // e.g. xtra-daemon, lowi-server
        // The .c_str() assignment below then takes care of trimming the cmdline at the first
        // 0x00. This is how original procrank worked (luckily)
        cmdline_ = cmdline.c_str();

        procmem_ = procmem.release();
        ;
        return true;
    }

    void CalcSwap(const uint16_t* swap_offset_array, float zram_compression_ratio) {
        const std::vector<uint16_t>& swp_offs = procmem_->SwapOffsets();
        for (auto& off : swp_offs) {
            proportional_swap_ += getpagesize() / swap_offset_array[off];
            unique_swap_ += swap_offset_array[off] == 1 ? getpagesize() : 0;
            zswap_ = proportional_swap_ * zram_compression_ratio;
        }
    }

    // Getters
    const pid_t& pid() const { return pid_; }
    const std::string& cmdline() const { return cmdline_; }
    const int32_t& oomadj() const { return oomadj_; }
    const uint64_t& proportional_swap() const { return proportional_swap_; }
    const uint64_t& unique_swap() const { return unique_swap_; }
    const uint64_t& zswap() const { return zswap_; }

    // Wrappers to ProcMemInfo
    const std::vector<uint16_t>& SwapOffsets() const { return procmem_->SwapOffsets(); }
    const ::android::meminfo::MemUsage& Usage() const { return procmem_->Usage(); }
    const ::android::meminfo::MemUsage& Wss() const { return procmem_->Wss(); }

  private:
    pid_t pid_;
    ::android::meminfo::ProcMemInfo* procmem_;
    int32_t oomadj_;
    std::string cmdline_;
    uint64_t proportional_swap_;
    uint64_t unique_swap_;
    uint64_t zswap_;
};

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

static bool read_all_pids(std::vector<pid_t>* pids) {
    pids->clear();
    std::unique_ptr<DIR, int (*)(DIR*)> procdir(opendir("/proc"), closedir);
    if (!procdir) return false;

    struct dirent* dir;
    pid_t pid;
    while ((dir = readdir(procdir.get()))) {
        if (!::android::base::ParseInt(dir->d_name, &pid)) continue;
        pids->emplace_back(pid);
    }

    return true;
}

static bool count_swap_offsets(const ProcessRecord& proc, uint16_t* swap_offset_array,
                               uint32_t size) {
    const std::vector<uint16_t>& swp_offs = proc.SwapOffsets();
    for (auto& off : swp_offs) {
        if (off >= size) {
            std::cerr << "swap offset " << off << " is out of bounds for process: " << proc.pid()
                      << std::endl;
            return false;
        }

        if (swap_offset_array[off] == USHRT_MAX) {
            std::cerr << "swap offset " << off << " ref count overflow in process: " << proc.pid()
                      << std::endl;
            return false;
        }

        swap_offset_array[off]++;
    }

    return true;
}

static void scan_header(std::stringstream& ss, bool show_wss, bool show_oomadj, bool has_swap,
                        bool has_zram) {
    ss.str("");
    ss << ::android::base::StringPrintf("%5s  ", "PID");
    if (show_oomadj) {
        ss << ::android::base::StringPrintf("%5s  ", "oom");
    }

    if (show_wss) {
        ss << ::android::base::StringPrintf("%7s  %7s  %7s  ", "WRss", "WPss", "WUss");
        if (has_swap) {
            ss << ::android::base::StringPrintf("%7s  %7s  %7s  ", "WSwap", "WPSwap", "WUSwap");
            if (has_zram) {
                ss << ::android::base::StringPrintf("%7s  ", "WZSwap");
            }
        }
    } else {
        ss << ::android::base::StringPrintf("%8s  %7s  %7s  %7s  ", "Vss", "Rss", "Pss", "Uss");
        if (has_swap) {
            ss << ::android::base::StringPrintf("%7s  %7s  %7s  ", "Swap", "PSwap", "USwap");
            if (has_zram) {
                ss << ::android::base::StringPrintf("%7s  ", "ZSwap");
            }
        }
    }

    ss << "cmdline";
}

static void scan_stats(std::stringstream& ss, ProcessRecord& proc, bool show_wss, bool show_oomadj,
                       bool has_swap, bool has_zram) {
    ss << ::android::base::StringPrintf("%5d  ", proc.pid());
    if (show_oomadj) {
        ss << ::android::base::StringPrintf("%5d  ", proc.oomadj());
    }

    if (show_wss) {
        ss << ::android::base::StringPrintf("%6zuK  %6zuK  %6zuK  ", proc.Wss().rss / 1024,
                                            proc.Wss().pss / 1024, proc.Wss().uss / 1024);
    } else {
        ss << ::android::base::StringPrintf("%7zuK  %6zuK  %6zuK  %6zuK  ", proc.Usage().vss / 1024,
                                            proc.Usage().rss / 1024, proc.Usage().pss / 1024,
                                            proc.Usage().uss / 1024);
    }

    if (has_swap) {
        ss << ::android::base::StringPrintf("%6zuK  ", proc.Usage().swap / 1024);
        ss << ::android::base::StringPrintf("%6zuK  ", proc.proportional_swap() / 1024);
        ss << ::android::base::StringPrintf("%6zuK  ", proc.unique_swap() / 1024);
        if (has_zram) {
            ss << ::android::base::StringPrintf("%6zuK  ", (proc.zswap() / 1024));
        }
    }
}

static void scan_separator(std::stringstream& ss, bool show_wss, bool show_oomadj, bool has_swap,
                           bool has_zram) {
    ss << ::android::base::StringPrintf("%5s  ", "");
    if (show_oomadj) {
        ss << ::android::base::StringPrintf("%5s  ", "");
    }

    if (show_wss) {
        ss << ::android::base::StringPrintf("%7s  %7s  %7s  ", "", "------", "------");
    } else {
        ss << ::android::base::StringPrintf("%8s  %7s  %7s  %7s  ", "", "", "------", "------");
    }

    if (has_swap) {
        ss << ::android::base::StringPrintf("%7s  %7s  %7s  ", "------", "------", "------");
        if (has_zram) {
            ss << ::android::base::StringPrintf("%7s  ", "------");
        }
    }

    ss << ::android::base::StringPrintf("%s", "------");
}

int main(int argc, char* argv[]) {
    bool show_wss = false;
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
                show_wss = true;
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

    // Get a list of all pids currently running in the system
    std::vector<pid_t> pids;
    if (!read_all_pids(&pids)) {
        std::cerr << "Failed to read all pids from the system" << std::endl;
        exit(EXIT_FAILURE);
    }

    // Figure out swap and zram
    uint64_t swap_total = smi.mem_swap_kb() * 1024;
    bool has_swap = swap_total > 0;
    bool has_zram = false;
    float zram_compression_ratio = 0.0;
    // Allocate the swap array
    std::unique_ptr<uint16_t, decltype(&free)> swap_offset_array(
            static_cast<uint16_t*>(calloc(swap_total / getpagesize(), sizeof(uint16_t))), free);
    if (has_swap) {
        has_zram = smi.mem_zram_kb() > 0;
        if (has_zram) {
            zram_compression_ratio = static_cast<float>(
                    smi.mem_zram_kb() / (smi.mem_swap_kb() - smi.mem_swap_free_kb()));
        }
    }

    // 1st pass through all processes to gather data for calculating proportional swap usage
    std::vector<ProcessRecord> procs;
    for (auto pid : pids) {
        ProcessRecord proc;
        if (!proc.Create(pid)) {
            std::cerr << "Failed to create process record for: " << pid << std::endl;
            continue;
        }

        // Skip processes with no memory mappings
        if (proc.Usage().vss == 0) continue;

        // collect swap_offset counts from all processes in 1st pass
        if (has_swap &&
            !count_swap_offsets(proc, swap_offset_array.get(), swap_total / getpagesize())) {
            std::cerr << "Failed to count swap offsets for process: " << pid << std::endl;
            continue;
        }

        procs.emplace_back(std::move(proc));
    }

    std::stringstream ss;
    if (procs.size() > 0) {
        scan_header(ss, show_wss, show_oomadj, has_swap, has_zram);
        ss << std::endl;
    }

    uint64_t total_pss = 0;
    uint64_t total_uss = 0;
    uint64_t total_swap = 0;
    uint64_t total_pswap = 0;
    uint64_t total_uswap = 0;
    uint64_t total_zswap = 0;
    // 2nd pass to calculate and get per process stats and add them up
    for (auto& proc : procs) {
        if (has_swap) {
            proc.CalcSwap(swap_offset_array.get(), zram_compression_ratio);
        }
        total_pss += proc.Usage().pss;
        total_uss += proc.Usage().uss;
        if (has_swap) {
            total_swap += proc.Usage().swap;
            total_pswap += proc.proportional_swap();
            total_uswap += proc.unique_swap();
            if (has_zram) {
                total_zswap += proc.zswap();
            }
        }

        scan_stats(ss, proc, show_wss, show_oomadj, has_swap, has_zram);
        ss << proc.cmdline() << std::endl;
    }

    // Add separator to output
    scan_separator(ss, show_wss, show_oomadj, has_swap, has_zram);
    ss << std::endl;

    // Add totals to output
    ss << ::android::base::StringPrintf("%5s  ", "");
    if (show_oomadj) {
        ss << ::android::base::StringPrintf("%5s  ", "");
    }

    if (show_wss) {
        ss << ::android::base::StringPrintf("%7s  %6" PRIu64 "K  %6" PRIu64 "K  ", "",
                                            total_pss / 1024, total_uss / 1024);
    } else {
        ss << ::android::base::StringPrintf("%8s  %7s  %6" PRIu64 "K  %6" PRIu64 "K  ", "", "",
                                            total_pss / 1024, total_uss / 1024);
    }

    if (has_swap) {
        ss << ::android::base::StringPrintf("%6" PRIu64 "K  ", total_swap / 1024);
        ss << ::android::base::StringPrintf("%6" PRIu64 "K  ", total_pswap / 1024);
        ss << ::android::base::StringPrintf("%6" PRIu64 "K  ", total_uswap / 1024);
        if (has_zram) {
            ss << ::android::base::StringPrintf("%6" PRIu64 "K  ", total_zswap / 1024);
        }
    }
    ss << "TOTAL";
    ss << std::endl << std::endl;

    if (has_swap) {
        ss << ::android::base::StringPrintf("ZRAM: %" PRIu64 "K physical used for %" PRIu64
                                            "K in swap "
                                            "(%" PRIu64 "K total swap)",
                                            smi.mem_zram_kb(),
                                            (smi.mem_swap_kb() - smi.mem_swap_free_kb()),
                                            smi.mem_swap_kb())
           << std::endl;
    }

    ss << ::android::base::StringPrintf(" RAM: %" PRIu64 "K total, %" PRIu64 "K free, %" PRIu64
                                        "K buffers, "
                                        "%" PRIu64 "K cached, %" PRIu64 "K shmem, %" PRIu64
                                        "K slab",
                                        smi.mem_total_kb(), smi.mem_free_kb(), smi.mem_buffers_kb(),
                                        smi.mem_cached_kb(), smi.mem_shmem_kb(), smi.mem_slab_kb())
       << std::endl;

    // dump on the screen
    std::cout << ss.str();

    return 0;
}

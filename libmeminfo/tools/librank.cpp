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
#include <linux/kernel-page-flags.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <iostream>
#include <memory>
#include <sstream>
#include <unordered_map>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>

#include <meminfo/procmeminfo.h>

using ::android::meminfo::MemUsage;
using ::android::meminfo::ProcMemInfo;
using ::android::meminfo::Vma;

static void usage(const char* myname) {
    std::cerr << "Usage: " << myname << " [ -P | -L ] [ -v | -r | -p | -u | -s | -h ]" << std::endl
              << std::endl
              << "Sort options:" << std::endl
              << "    -v  Sort processes by VSS." << std::endl
              << "    -r  Sort processes by RSS." << std::endl
              << "    -p  Sort processes by PSS." << std::endl
              << "    -u  Sort processes by USS." << std::endl
              << "    -s  Sort processes by swap." << std::endl
              << "        (Default sort order is PSS.)" << std::endl
              << "    -a  Show all mappings, including stack, heap and anon." << std::endl
              << "    -P /path  Limit libraries displayed to those in path." << std::endl
              << "    -R  Reverse sort order (default is descending)." << std::endl
              << "    -m [r][w][x] Only list pages that exactly match permissions" << std::endl
              << "    -c  Only show cached (storage backed) pages" << std::endl
              << "    -C  Only show non-cached (ram/swap backed) pages" << std::endl
              << "    -k  Only show pages collapsed by KSM" << std::endl
              << "    -h  Display this help screen." << std::endl;
}

static void add_mem_usage(MemUsage* to, const MemUsage& from) {
    to->vss += from.vss;
    to->rss += from.rss;
    to->pss += from.pss;
    to->uss += from.uss;

    to->swap += from.swap;

    to->private_clean += from.private_clean;
    to->private_dirty += from.private_dirty;

    to->shared_clean += from.shared_clean;
    to->shared_dirty += from.shared_dirty;
}

struct ProcessRecord {
  public:
    ProcessRecord(pid_t pid) : pid_(-1), cmdline_("") {
        std::string fname = ::android::base::StringPrintf("/proc/%d/cmdline", pid);
        std::string cmdline;
        if (!::android::base::ReadFileToString(fname, &cmdline)) {
            std::cerr << "Failed to read cmdline from: " << fname << std::endl;
            return;
        }
        // We deliberately don't read the proc/<pid>cmdline file directly into 'cmdline_'
        // because of some processes showing up cmdlines that end with "0x00 0x0A 0x00"
        // e.g. xtra-daemon, lowi-server
        // The .c_str() assignment below then takes care of trimming the cmdline at the first
        // 0x00. This is how original procrank worked (luckily)
        cmdline_ = cmdline.c_str();
        pid_ = pid;
    }

    ~ProcessRecord() = default;

    bool valid() const { return pid_ != -1; }

    // Getters
    const pid_t& pid() const { return pid_; }
    const std::string& cmdline() const { return cmdline_; }
    const MemUsage& usage() const { return usage_; }

    // Add to the usage
    void AddUsage(const MemUsage& mem_usage) { add_mem_usage(&usage_, mem_usage); }

  private:
    pid_t pid_;
    std::string cmdline_;
    MemUsage usage_;
};

struct LibRecord {
  public:
    LibRecord(std::string name) : name_(name) {}
    ~LibRecord() = default;

    const std::string& name() const { return name_; }
    const MemUsage& total_usage() const { return total_usage_; }
    const std::vector<std::shared_ptr<ProcessRecord>>& processes() const { return procs_; }
    void AddUsage(std::shared_ptr<ProcessRecord> proc, const MemUsage& usage) {
        add_mem_usage(&total_usage_, usage);
        proc->AddUsage(usage);
        if (std::find(procs_.begin(), procs_.end(), proc) == procs_.end()) {
            procs_.push_back(proc);
        }
    }

  private:
    std::string name_;
    MemUsage total_usage_;
    std::vector<std::shared_ptr<ProcessRecord>> procs_;
};

// map of all libraries
std::unordered_map<std::string, LibRecord> libs;

static bool read_all_pids(std::function<bool(pid_t pid)> for_each_pid) {
    std::unique_ptr<DIR, int (*)(DIR*)> procdir(opendir("/proc"), closedir);
    if (!procdir) return false;

    struct dirent* dir;
    pid_t pid;
    while ((dir = readdir(procdir.get()))) {
        if (!::android::base::ParseInt(dir->d_name, &pid)) continue;
        if (!for_each_pid(pid)) return false;
    }

    return true;
}

// Global flags
uint64_t pgflags;
uint64_t pgflags_mask;

bool has_swap = false;

bool scan_libs_per_process(pid_t pid) {
    ProcMemInfo pmem(pid, false, pgflags, pgflags_mask);
    const std::vector<Vma> maps = pmem.Maps();
    if (maps.size() == 0) {
        // nothing to do here, continue
        return true;
    }

    auto proc = std::make_shared<ProcessRecord>(pid);
    if (!proc->valid()) {
        std::cerr << "Failed to create process record for process: " << pid << std::endl;
        return false;
    }

    for (auto& map : maps) {
        // TOOD: Skip maps based on prefix
        // TODO: Skip maps based on permissions
        // TODO: Skip maps based on blacklisted names

        std::pair<std::unordered_map<std::string, LibRecord>::iterator, bool> result =
                libs.emplace(map.name, map.name);
        LibRecord& lib = result.first->second;
        lib.AddUsage(proc, map.usage);

        if (!has_swap && map.usage.swap) {
            has_swap = true;
        }
    }

    return true;
}

int main(int argc, char* argv[]) {
    int opt;

    while ((opt = getopt(argc, argv, "acChkm:pP:uvrsR")) != -1) {
        switch (opt) {
            case 'a':
                break;
            case 'c':
                pgflags = 0;
                pgflags_mask = (1 << KPF_SWAPBACKED);
                break;
            case 'C':
                pgflags = pgflags_mask = (1 << KPF_SWAPBACKED);
                break;
            case 'h':
                usage(argv[0]);
                return 0;
                break;
            case 'k':
                pgflags = pgflags_mask = (1 << KPF_KSM);
                break;
            case 'm':
                break;
            case 'p':
                break;
            case 'P':
                break;
            case 'u':
                break;
            case 'v':
                break;
            case 'r':
                break;
            case 's':
                break;
            case 'R':
                break;
            default:
                abort();
        }
    }

    if (!read_all_pids(scan_libs_per_process)) {
        std::cerr << "Failed to read all pids from the system" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::stringstream ss;
    ss << ::android::base::StringPrintf(" %6s   %7s   %6s   %6s   %6s  ", "RSStot", "VSS", "RSS",
                                        "PSS", "USS");
    if (has_swap) {
        ss << ::android::base::StringPrintf(" %6s  ", "Swap");
    }
    ss << "Name/PID" << std::endl;

    for (auto& l : libs) {
        LibRecord& lib = l.second;
        ss << ::android::base::StringPrintf("%6zdK   %7s   %6s   %6s   %6s  ",
                                            lib.total_usage().pss / 1024, "", "", "", "");
        if (has_swap) {
            ss << ::android::base::StringPrintf(" %6s  ", "");
        }
        ss << ::android::base::StringPrintf("%s", lib.name().c_str()) << std::endl;

        // TODO: Sort library mappings according to the options here
        for (auto& p : lib.processes()) {
            const MemUsage& usage = p->usage();
            ss << ::android::base::StringPrintf(
                    " %6s  %7" PRIu64 "K  %6" PRIu64 "K  %6" PRIu64 "K  %6" PRIu64 "K  ", "",
                    usage.vss / 1024, usage.rss / 1024, usage.pss / 1024, usage.uss / 1024);
            if (has_swap) {
                ss << ::android::base::StringPrintf("%6" PRIu64 "K  ", usage.swap / 1024);
            }
            ss << ::android::base::StringPrintf("  %s [%d]", p->cmdline().c_str(), p->pid())
               << std::endl;
        }
    }

    std::cout << ss.str();

    return 0;
}

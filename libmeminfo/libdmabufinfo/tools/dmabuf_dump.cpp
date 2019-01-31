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
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>

#include <android-base/stringprintf.h>
#include <dmabufinfo/dmabufinfo.h>

using DmaBuffer = ::android::dmabufinfo::DmaBuffer;

[[noreturn]] static void usage(int exit_status) {
    fprintf(stderr,
            "Usage: %s < pid | -a > \n"
            "    pid Print dmabuf information for this process.\n"
            "    -a  Print dmabuf information for all processes.\n",
            getprogname());

    exit(exit_status);
}

static std::string GetProcessBaseName(pid_t pid) {
    std::string pid_path = android::base::StringPrintf("/proc/%d/comm", pid);
    std::ifstream in{pid_path};
    if (!in) return std::string("N/A");
    std::string line;
    std::getline(in, line);
    if (!in) return std::string("N/A");
    return line;
}

static void AddPidsToSet(const std::unordered_map<pid_t, int>& map, std::set<pid_t>* set)
{
    for (auto it = map.begin(); it != map.end(); ++it)
        set->insert(it->first);
}

static void PrintDmaBufInfo(const std::vector<DmaBuffer>& bufs, std::stringstream& ss) {
    std::set<pid_t> pid_set;
    std::set<pid_t>::iterator it;
    std::map<pid_t, int> pid_column;

    if (!bufs.size()) {
        ss << "dmabuf info not found ¯\\_(ツ)_/¯\n";
        return;
    }

    // Find all uniquie pids in the input vector, create a set
    for (int i = 0; i < bufs.size(); i++) {
        AddPidsToSet(bufs[i].fdrefs(), &pid_set);
        AddPidsToSet(bufs[i].maprefs(), &pid_set);
    }

    int pid_count = 0;

    ss << "\t\t\t\t\t\t";

    // Create a map to convert each unique pid into a column number
    for (it = pid_set.begin(); it != pid_set.end(); ++it, ++pid_count) {
        pid_column.insert(std::make_pair(*it, pid_count));
        ss << ::android::base::StringPrintf("[pid: % 4d]\t", *it);
    }

    ss << "\n\t\t\t\t\t\t";

    for (it = pid_set.begin(); it != pid_set.end(); ++it) {
        ss << ::android::base::StringPrintf("%16s", GetProcessBaseName(*it).c_str());
    }

    ss << "\n\tinode\t\tsize\t\tcount\t";
    for (int i = 0; i < pid_count; i++) ss << "fd\tmap\t";
    ss << "\n";

    int* fds = new int[pid_count];
    int* maps = new int[pid_count];
    long* pss = new long[pid_count];

    memset(pss, 0, sizeof(long) * pid_count);

    for (int i = 0; i < bufs.size(); i++) {
        const DmaBuffer* buf=&bufs[i];

        ss << ::android::base::StringPrintf("%16lu\t%10" PRIu64 "\t%lu\t", buf->inode(),buf->size(),
                buf->count());

        memset(fds, 0, sizeof(int) * pid_count);
        memset(maps, 0, sizeof(int) * pid_count);

        for (auto it = buf->fdrefs().begin(); it != buf->fdrefs().end(); ++it) {
            fds[pid_column[it->first]] = it->second;
            pss[pid_column[it->first]] += buf->size() * it->second / buf->count();
        }

        for (auto it = buf->maprefs().begin(); it != buf->maprefs().end(); ++it) {
            maps[pid_column[it->first]] = it->second;
            pss[pid_column[it->first]] += buf->size() * it->second / buf->count();
        }

        for (int i = 0; i < pid_count; i++) {
            ss << ::android::base::StringPrintf("%d\t%d\t", fds[i], maps[i]);
        }
        ss << "\n";
    }
    ss << "-----------------------------------------\n";
    ss << "PSS                                      ";
    for (int i = 0; i < pid_count; i++) {
        ss << ::android::base::StringPrintf("%15ldK", pss[i] / 1024);
    }
    ss << "\n";
}

static int show(const std::vector<DmaBuffer>& bufs) {
    std::stringstream ss;
    PrintDmaBufInfo(bufs, ss);
    std::cout << ss.str();
    return 0;
}

int main(int argc, char* argv[]) {
    int opt;
    pid_t pid = -1;
    bool show_all = false;
    std::vector<DmaBuffer> bufs;

    while ((opt = getopt(argc, argv, "a")) != -1) {
        switch (opt) {
            case 'a':
                show_all = true;
                break;
            case '?':
                usage(EXIT_SUCCESS);
            default:
                usage(EXIT_FAILURE);
        }
    }

    if (!show_all) {
        if (optind != (argc - 1)) {
            fprintf(stderr, "No pid provided\n");
            usage(EXIT_FAILURE);
        }
        pid = atoi(argv[optind]);
        if (pid == 0) {
            std::cerr << "Invalid process id" << std::endl;
            exit(EXIT_FAILURE);
        }
        if (!ReadDmaBufInfo(pid, &bufs)) {
            std::cerr << "Unable to read dmabuf info" << std::endl;
            exit(EXIT_FAILURE);
        }
    }
    else {
        if (!ReadDmaBufInfo(&bufs)) {
            std::cerr << "Unable to read DEBUGFS dmabuf info" << std::endl;
            exit(EXIT_FAILURE);
        }

        std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir("/proc"), closedir);
        if (!dir) {
            std::cerr << "Failed to open /proc directory" << std::endl;
            exit(EXIT_FAILURE);
        }

        struct dirent* dent;
        while ((dent = readdir(dir.get()))) {
            if (dent->d_type != DT_DIR) continue;

            int matched = sscanf(dent->d_name, "%d", &pid);
            if (matched != 1) continue;

            if (!AppendDmaBufInfo(pid, &bufs)) {
                std::cerr << "Unable to read dmabuf info for pid " << pid << std::endl;
                exit(EXIT_FAILURE);
            }
        }
    }
    show(bufs);
    return 0;
}



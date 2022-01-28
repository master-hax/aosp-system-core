/*
 * Copyright 2022, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <set>
#include <string>

#include <android/os/DropBoxManager.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>

#include "dmesg_parser.h"

const char kTraceFile[] = "/sys/kernel/tracing/instances/bootreceiver/trace_pipe";

// If there are too many reports, the device is horribly broken.
const unsigned int kMaxReports = 10;
std::set<std::string> sent_reports;

const char kUnknown[] = "UNKNOWN";

static std::string GetOneBootHeader(const std::string& pretty, const std::string& pname) {
    return pretty + ": " + android::base::GetProperty(pname, kUnknown) + "\n";
};

static std::string GetBootHeaders() {
    std::string ret = GetOneBootHeader("Build", "ro.build.fingerprint");
    ret += GetOneBootHeader("Hardware", "ro.product.board");
    ret += GetOneBootHeader("Revision", "ro.revision");
    ret += GetOneBootHeader("Bootloader", "ro.bootloader");
    ret += GetOneBootHeader("Radio", "gsm.version.baseband");

    std::string version;
    if (!android::base::ReadFileToString("/proc/version", &version)) version = kUnknown;
    ret += "Kernel: " + version + "\n\n";
    return ret;
}

static bool StoreReport(const std::string& tag, const std::string& report) {
    std::string boot_headers = GetBootHeaders();
    android::sp<android::os::DropBoxManager> dropbox(new android::os::DropBoxManager());
    auto status = dropbox->addText(android::String16(tag.c_str()), boot_headers + report);
    if (!status.isOk()) {
        LOG(ERROR) << "Dropbox failed";
        return false;
    }
    return true;
}

static bool ProcessDmesg() {
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen("dmesg", "r"), pclose);
    if (!pipe) {
        PLOG(ERROR) << "popen() failed!";
        return false;
    }
    dmesg_parser::DmesgParser dmesg_parser;

    char* buffer = NULL;
    size_t buffer_size = 0;
    while (getline(&buffer, &buffer_size, pipe.get()) != -1) {
        std::string line(buffer);
        if (line.back() != '\n') line += "\n";
        dmesg_parser.ProcessLine(line);
        if (dmesg_parser.ReportReady()) {
            std::string tag = "SYSTEM_" + dmesg_parser.ReportType() + "_ERROR_REPORT";
            std::string title = dmesg_parser.ReportTitle();
            if ((sent_reports.find(title) == sent_reports.end()) &&
                (sent_reports.size() < kMaxReports)) {
                if (StoreReport(tag, dmesg_parser.FlushReport())) sent_reports.insert(title);
            }
        }
    }
    free(buffer);
    return true;
}

int main(int, char*[]) {
    android::base::unique_fd epoll_fd(epoll_create1(0));
    if (!epoll_fd.get()) {
        PLOG(ERROR) << "failed to create epoll fd";
        return 1;
    }

    android::base::unique_fd trace_fd(open(kTraceFile, O_RDONLY));
    if (!trace_fd.get()) {
        PLOG(ERROR) << "failed to open " << kTraceFile;
    }

    struct epoll_event event;
    event.events = EPOLLET | EPOLLIN;
    event.data.fd = trace_fd.get();

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, trace_fd.get(), &event)) {
        PLOG(ERROR) << "epoll_ctl() failed";
        return 1;
    }

    while (true) {
        int ret = TEMP_FAILURE_RETRY(epoll_wait(epoll_fd.get(), &event, 1, -1));
        if (ret < 0) {
            PLOG(ERROR) << "epoll_wait() failed";
            return 1;
        }
        if (ret && !ProcessDmesg()) {
            LOG(ERROR) << "processDmesg() failed";
            return 1;
        }
    }
    return 0;
}

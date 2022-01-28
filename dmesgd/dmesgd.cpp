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

volatile bool glob = true;

const char kTraceFile[] = "/sys/kernel/tracing/instances/bootreceiver/trace_pipe";
const char kUnknown[] = "UNKNOWN";
std::vector<std::pair<std::string, std::string>> kHeaderProperties = {
        {"Build", "ro.build.fingerprint"}, {"Hardware", "ro.product.board"},
        {"Revision", "ro.revision"},       {"Bootloader", "ro.bootloader"},
        {"Radio", "gsm.version.baseband"},
};

// If there are too many reports, the device is horribly broken.
const unsigned int kMaxReports = 10;
std::set<std::string> sent_reports;

static std::string getBootHeaders() {
    std::string ret = "";
    for (auto p : kHeaderProperties) {
        std::string prop = android::base::GetProperty(p.second, kUnknown);
        ret += p.first + ": " + prop + "\n";
    }
    std::string version;
    if (!android::base::ReadFileToString("/proc/version", &version)) version = kUnknown;
    ret += "Kernel: " + version + "\n\n";
    return ret;
}

static bool storeReport(const std::string& tag, const std::string& report) {
    std::string boot_headers = getBootHeaders();
    android::sp<android::os::DropBoxManager> dropbox(new android::os::DropBoxManager());
    auto status = dropbox->addText(android::String16(tag.c_str()), boot_headers + report);
    if (!status.isOk()) {
        LOG(ERROR) << "Dropbox failed";
        return false;
    }
    return true;
}

static bool processDmesg() {
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen("dmesg", "r"), pclose);
    if (!pipe) {
        LOG(ERROR) << "popen() failed!";
        return false;
    }
    std::array<char, 128> buffer;
    std::string result;
    dmesg_parser::DmesgParser dmesg_parser;

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        std::size_t newline;
        std::string buffer_s(buffer.data());
        do {
            newline = buffer_s.find('\n');
            if (newline == std::string::npos) {
                result += buffer_s;
                break;
            } else {
                result += buffer_s.substr(0, newline + 1);
                dmesg_parser.processLine(result);
                buffer_s = buffer_s.substr(newline + 1);
                result = "";
                if (dmesg_parser.reportReady()) {
                    std::string tag = "SYSTEM_" + dmesg_parser.reportType() + "_ERROR_REPORT";
                    std::string title = dmesg_parser.reportTitle();
                    if ((sent_reports.find(title) != sent_reports.end()) &&
                        (sent_reports.size() < kMaxReports)) {
                        if (storeReport(tag, dmesg_parser.flushReport()))
                            sent_reports.insert(title);
                    }
                }
            }
        } while (true);
    }
    return true;
}

int main(int, char*[]) {
    android::base::unique_fd epoll_fd(epoll_create1(0));
    if (!epoll_fd.get()) {
        LOG(ERROR) << "failed to create epoll fd";
        return 1;
    }

    android::base::unique_fd trace_fd(open(kTraceFile, O_RDONLY));
    if (!trace_fd.get()) {
        LOG(ERROR) << "failed to open " << kTraceFile;
    }

    struct epoll_event event;
    event.events = EPOLLET | EPOLLIN;
    event.data.fd = trace_fd.get();

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, trace_fd.get(), &event)) {
        LOG(ERROR) << "epoll_ctl() failed";
        return 1;
    }

    while (true) {
        epoll_wait(epoll_fd.get(), &event, 1, -1);
        if (!processDmesg()) {
            LOG(ERROR) << "processDmesg() failed";
            return 1;
        }
    }
    return 0;
}

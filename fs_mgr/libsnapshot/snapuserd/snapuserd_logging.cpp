// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include "snapuserd_logging.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string.h>

#include <array>
#include <cstdio>
#include <string>

#include <mutex>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <fstab/fstab.h>

namespace android::snapshot {

namespace {
static constexpr auto&& LOG_DIR = "/data/misc/snapuserd_log/";

time_t GetSystemBootTimestamp() {
    static constexpr std::string_view btime = "btime";
    std::string proc_stat;
    if (!android::base::ReadFileToString("/proc/stat", &proc_stat)) {
        return time(nullptr);
    }
    auto pos = proc_stat.find(btime);
    if (pos == std::string::npos) {
        return time(nullptr);
    }

    time_t boot_time{};
    if (!sscanf(proc_stat.data() + pos + btime.size(), "%ld", &boot_time)) {
        return time(nullptr);
    }

    return boot_time;
}

std::string GetTimeAsString() {
    auto utime = GetSystemBootTimestamp();
    struct tm tm {};
    CHECK_EQ(localtime_r(&utime, &tm), &tm);
    char str[16];
    CHECK_EQ(strftime(str, sizeof(str), "%Y%m%d-%H%M%S", &tm), 15u);
    return str;
}

int OpenLogFile() {
    static const std::string log_file =
            std::string(LOG_DIR) + "snapuserd." + GetTimeAsString() + ".txt";
    int fd = open(log_file.c_str(), O_CREAT | O_CLOEXEC | O_RDWR | O_APPEND | O_DSYNC, 0644);
    if (fd < 0) {
        std::string err_msg = "Failed to open " + log_file + ": " + strerror(errno);
        android::base::KernelLogger(android::base::LogId::SYSTEM, android::base::LogSeverity::ERROR,
                                    "snapuserd", __FILE__, __LINE__, err_msg.c_str());
    }
    return fd;
}

bool IsDataMounted() {
    android::fs_mgr::Fstab fstab;
    if (!ReadFstabFromFile("/proc/mounts", &fstab)) {
        return false;
    }
    return GetEntryForMountPoint(&fstab, "/data") != nullptr;
}

bool WriteToLogFile(void* data, size_t size) {
    //	-2 means uninitialized, -1 means initialization failed
    static int fd = -2;
    // 1MB in memory buffer to cache logs before /data is mounted
    static std::array<char, 1024 * 1024> buf;
    static size_t bytes_cached = 0;

    if (fd == -2) {
        if (IsDataMounted()) {
            fd = OpenLogFile();
            if (fd >= 0) {
                android::base::WriteFully(fd, buf.data(), bytes_cached);
                bytes_cached = 0;
            }
        } else {
            const auto bytes_to_copy = std::min(size, buf.size() - bytes_cached);
            memcpy(buf.data() + bytes_cached, data, bytes_to_copy);
            bytes_cached += bytes_to_copy;
        }
    }
    if (fd >= 0) {
        return android::base::WriteFully(fd, data, size);
    }
    // fd is still -1 after initialization, this means we failed to open log files.
    // Maybe log to logcat?
    return false;
}

constexpr const char* SeverityAsString(android::base::LogSeverity severity) {
    switch (severity) {
        case android::base::LogSeverity::VERBOSE:
            return "VERBOSE";
        case android::base::LogSeverity::DEBUG:
            return "DEBUG";
        case android::base::LogSeverity::INFO:
            return "INFO";
        case android::base::LogSeverity::WARNING:
            return "WARN";
        case android::base::LogSeverity::ERROR:
            return "ERROR";
        case android::base::LogSeverity::FATAL:
            return "FATAL";
        default:
            return "UNKNOWN";
    }
}

void CachedFileLogger(android::base::LogId /*id*/, android::base::LogSeverity severity,
                      const char* /*tag*/, const char* file, unsigned int line,
                      const char* message) {
    static std::array<char, 1024> buf;
    timeval tv{};
    gettimeofday(&tv, nullptr);
    time_t t = tv.tv_sec;
    struct tm local_time {};
    localtime_r(&t, &local_time);
    std::string_view line_msg = message;
    const auto bytes_written =
            snprintf(buf.data(), buf.size(), "[%02d%02d/%02d%02d%02d.%ld] [%s:%s(%d)] ",
                     local_time.tm_mon, local_time.tm_mday, local_time.tm_hour, local_time.tm_min,
                     local_time.tm_sec, tv.tv_usec, SeverityAsString(severity), file, line);
    const auto bytes_to_copy = std::min(buf.size() - bytes_written - 1, line_msg.size());
    memcpy(buf.data() + bytes_written, line_msg.data(), bytes_to_copy);
    buf[bytes_to_copy + bytes_written] = '\n';
    WriteToLogFile(buf.data(), bytes_written + bytes_to_copy + 1);
}

void CombinedLogger(android::base::LogId id, android::base::LogSeverity severity, const char* tag,
                    const char* file, unsigned int line, const char* message) {
    android::base::KernelLogger(id, severity, tag, file, line, message);
    CachedFileLogger(id, severity, tag, file, line, message);
}

void DeleteOldLogs() {
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(LOG_DIR), &closedir);
    if (dir.get() == nullptr) {
        return;
    }

    std::vector<std::string> log_files;
    while (auto dirent = readdir(dir.get())) {
        std::string filename = dirent->d_name;
        if (android::base::StartsWith(filename, "snapuserd.")) {
            log_files.emplace_back(std::move(filename));
        }
    }
    std::sort(log_files.begin(), log_files.end(), std::greater<>());
    // Keep the newest logs, remove the rest
    for (size_t i = 10; i < log_files.size(); ++i) {
        const auto path = LOG_DIR + log_files[i];
        unlink(path.c_str());
    }
}

}  // namespace

void SetupLogging(char** argv) {
    DeleteOldLogs();
    android::base::InitLogging(argv, &CombinedLogger);
}

}  // namespace android::snapshot
/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "task_profiles.h"
#include <android-base/logging.h>
#include <gtest/gtest.h>
#include <unistd.h>

using android::base::LogFunction;
using android::base::LogId;
using android::base::LogSeverity;
using android::base::SetLogger;

class ScopedLogCapturer {
  public:
    struct log_args {
        LogId log_buffer_id;
        LogSeverity severity;
        std::string tag;
        std::string file;
        unsigned int line;
        std::string message;
    };

    // Constructor. Installs a new logger and saves the currently active logger.
    ScopedLogCapturer() {
        saved_logger_ = SetLogger([this](LogId log_buffer_id, LogSeverity severity, const char* tag,
                                         const char* file, unsigned int line, const char* message) {
            if (saved_logger_) {
                saved_logger_(log_buffer_id, severity, tag, file, line, message);
            }
            log_.emplace_back(log_args{.log_buffer_id = log_buffer_id,
                                       .severity = severity,
                                       .tag = tag,
                                       .file = file,
                                       .line = line,
                                       .message = message});
        });
    }
    // Destructor. Restores the original logger.
    ~ScopedLogCapturer() { SetLogger(std::move(saved_logger_)); }
    ScopedLogCapturer(const ScopedLogCapturer&) = delete;
    ScopedLogCapturer& operator=(const ScopedLogCapturer&) = delete;
    // Returns the logged lines.
    const std::vector<log_args>& Log() const { return log_; }

  private:
    LogFunction saved_logger_;
    std::vector<log_args> log_;
};

// cgroup attribute at the top level of the cgroup hierarchy.
class ProfileAttributeMock : public IProfileAttribute {
  public:
    ProfileAttributeMock(const std::string& file_name) : file_name_(file_name) {}
    ~ProfileAttributeMock() override = default;
    void Reset(const CgroupController& controller, const std::string& file_name) override {
        CHECK(false);
    }
    const CgroupController* controller() const override {
        CHECK(false);
        return {};
    }
    const std::string& file_name() const override { return file_name_; }
    bool GetPathForTask(int tid, std::string* path) const override {
        *path = "/sys/fs/cgroup/" + file_name_;
        return true;
    };

  private:
    const std::string file_name_;
};

// Test that an attempt to set a non-existing cgroup attribute causes an error message to be logged.
TEST(SetAttributeAction, SetNonExistingAttributeFails) {
    ScopedLogCapturer captured_log;
    ProfileAttributeMock pa("no-such-attribute");
    SetAttributeAction a(&pa, "no-such-attribute", /*optional=*/false);
    a.ExecuteForProcess(getuid(), getpid());
    auto log = captured_log.Log();
    ASSERT_EQ(log.size(), 1);
    EXPECT_EQ(log[0].message.find("Failed to write"), 0);
    EXPECT_NE(log[0].message.find("Permission denied"), std::string::npos);
}

// Test that an attempt to set a read-only cgroup attribute causes an error message to be logged.
TEST(SetAttributeAction, SetRoAttributeFails) {
    ScopedLogCapturer captured_log;
    ProfileAttributeMock pa("cgroup.stats");
    SetAttributeAction a(&pa, "cgroup.stats", /*optional=*/false);
    a.ExecuteForProcess(getuid(), getpid());
    auto log = captured_log.Log();
    ASSERT_EQ(log.size(), 1);
    EXPECT_EQ(log[0].message.find("Failed to write"), 0);
    EXPECT_NE(log[0].message.find("Permission denied"), std::string::npos);
}

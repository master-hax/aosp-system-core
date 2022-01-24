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
#include <processgroup/processgroup.h>
#include <unistd.h>

using ::android::base::ERROR;
using ::android::base::LogFunction;
using ::android::base::LogId;
using ::android::base::LogSeverity;
using ::android::base::SetLogger;
using ::android::base::VERBOSE;
using ::testing::TestWithParam;
using ::testing::Values;

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
        saved_severity_ = SetMinimumLogSeverity(android::base::VERBOSE);
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
    // Destructor. Restores the original logger and log level.
    ~ScopedLogCapturer() {
        SetLogger(std::move(saved_logger_));
        SetMinimumLogSeverity(saved_severity_);
    }
    ScopedLogCapturer(const ScopedLogCapturer&) = delete;
    ScopedLogCapturer& operator=(const ScopedLogCapturer&) = delete;
    // Returns the logged lines.
    const std::vector<log_args>& Log() const { return log_; }

  private:
    LogSeverity saved_severity_;
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
        if (access("/system", 0) >= 0) {
            // Android.
            CHECK(CgroupGetControllerPath(CGROUPV2_CONTROLLER_NAME, path));
            CHECK_GT(path->length(), 0);
            if (path->rbegin()[0] != '/') {
                *path += "/";
            }
        } else {
            // Not Android.
            *path = "/sys/fs/cgroup/";
        }
        *path += file_name_;
        return true;
    };

  private:
    const std::string file_name_;
};

struct TestParam {
    const char* attr_name;
    const char* attr_value;
    bool optional_attr;
    LogSeverity log_severity;
    const char* log_pfx;
    const char* log_suffix;
};

class SetAttributeFixture : public TestWithParam<TestParam> {
  public:
    ~SetAttributeFixture() = default;
};

TEST_P(SetAttributeFixture, SetAttribute) {
    // This test must be run with root privileges.
    ASSERT_EQ(geteuid(), 0);
    const TestParam params = GetParam();
    ScopedLogCapturer captured_log;
    ProfileAttributeMock pa(params.attr_name);
    SetAttributeAction a(&pa, params.attr_value, params.optional_attr);
    a.ExecuteForProcess(getuid(), getpid());
    auto log = captured_log.Log();
    ASSERT_EQ(log.size(), 1);
    EXPECT_EQ(log[0].severity, params.log_severity);
    ASSERT_TRUE(params.log_pfx);
    EXPECT_EQ(log[0].message.find(params.log_pfx), 0);
    ASSERT_TRUE(params.log_suffix);
    EXPECT_NE(log[0].message.find(params.log_suffix), std::string::npos);
}

INSTANTIATE_TEST_SUITE_P(SetAttributeTestSuite, SetAttributeFixture,
                         Values(TestParam{.attr_name = "no-such-attribute",
                                          .attr_value = ".",
                                          .optional_attr = false,
                                          .log_severity = ERROR,
                                          .log_pfx = "Failed to write",
                                          .log_suffix = "Permission denied"},
                                TestParam{.attr_name = "no-such-attribute",
                                          .attr_value = ".",
                                          .optional_attr = true,
                                          .log_severity = VERBOSE,
                                          .log_pfx = "Did not write",
                                          .log_suffix = "(not writeable)"},
                                TestParam{.attr_name = "cgroup.procs",
                                          .attr_value = ".",
                                          .optional_attr = true,
                                          .log_severity = ERROR,
                                          .log_pfx = "Failed to write",
                                          .log_suffix = "Invalid argument"},
                                TestParam{.attr_name = "cgroup.stat",
                                          .attr_value = ".",
                                          .optional_attr = false,
                                          .log_severity = ERROR,
                                          .log_pfx = "Failed to write",
                                          .log_suffix = "Invalid argument"}));

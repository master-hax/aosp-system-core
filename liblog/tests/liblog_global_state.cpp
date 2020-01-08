/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define LOG_TAG "global_state_test_tag"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android/log.h>

#include <gtest/gtest.h>

TEST(global_state, libbase_logs_with_libbase_SetLogger) {
  using namespace android::base;
  bool message_seen = false;
  LogSeverity expected_severity = WARNING;
  std::string expected_file = Basename(__FILE__);
  unsigned int expected_line;
  std::string expected_message = "libbase test message";

  auto LoggerFunction = [&](LogId log_id, LogSeverity severity, const char* tag, const char* file,
                            unsigned int line, const char* message) {
    message_seen = true;
    EXPECT_EQ(DEFAULT, log_id);
    EXPECT_EQ(expected_severity, severity);
    EXPECT_STREQ(LOG_TAG, tag);
    EXPECT_EQ(expected_file, file);
    EXPECT_EQ(expected_line, line);
    EXPECT_EQ(expected_message, message);
  };

  SetLogger(LoggerFunction);

  expected_line = __LINE__ + 1;
  LOG(expected_severity) << expected_message;
  EXPECT_TRUE(message_seen);
}

TEST(global_state, libbase_logs_with_liblog_set_logger) {
  using namespace android::base;
  // These must be static since they're used by the liblog logger function, which only accepts
  // lambdas without captures.  The items used by the libbase logger are explicitly not static, to
  // ensure that lambdas with captures do work there.
  static bool message_seen = false;
  static std::string expected_file = Basename(__FILE__);
  static unsigned int expected_line;
  static std::string expected_message = "libbase test message";

  auto liblog_logger_function = [](const struct __android_logger_data* logger_data,
                                   const char* message) {
    message_seen = true;
    EXPECT_EQ(sizeof(__android_logger_data), logger_data->struct_size);
    EXPECT_EQ(LOG_ID_DEFAULT, logger_data->buffer_id);
    EXPECT_EQ(ANDROID_LOG_WARN, logger_data->priority);
    EXPECT_STREQ(LOG_TAG, logger_data->tag);
    EXPECT_EQ(expected_file, logger_data->file);
    EXPECT_EQ(expected_line, logger_data->line);
    EXPECT_EQ(expected_message, message);
  };

  __android_log_set_logger(liblog_logger_function);

  expected_line = __LINE__ + 1;
  LOG(WARNING) << expected_message;
  EXPECT_TRUE(message_seen);
}

TEST(global_state, liblog_logs_with_libbase_SetLogger) {
  using namespace android::base;
  bool message_seen = false;
  std::string expected_message = "libbase test message";

  auto LoggerFunction = [&](LogId log_id, LogSeverity severity, const char* tag, const char* file,
                            unsigned int line, const char* message) {
    message_seen = true;
    EXPECT_EQ(MAIN, log_id);
    EXPECT_EQ(WARNING, severity);
    EXPECT_STREQ(LOG_TAG, tag);
    EXPECT_EQ(nullptr, file);
    EXPECT_EQ(0U, line);
    EXPECT_EQ(expected_message, message);
  };

  SetLogger(LoggerFunction);

  __android_log_buf_write(LOG_ID_MAIN, ANDROID_LOG_WARN, LOG_TAG, expected_message.c_str());
  EXPECT_TRUE(message_seen);
  message_seen = false;
}

TEST(global_state, liblog_logs_with_liblog_set_logger) {
  using namespace android::base;
  // These must be static since they're used by the liblog logger function, which only accepts
  // lambdas without captures.  The items used by the libbase logger are explicitly not static, to
  // ensure that lambdas with captures do work there.
  static bool message_seen = false;
  static int expected_buffer_id = LOG_ID_MAIN;
  static int expected_priority = ANDROID_LOG_WARN;
  static std::string expected_message = "libbase test message";

  auto liblog_logger_function = [](const struct __android_logger_data* logger_data,
                                   const char* message) {
    message_seen = true;
    EXPECT_EQ(sizeof(__android_logger_data), logger_data->struct_size);
    EXPECT_EQ(expected_buffer_id, logger_data->buffer_id);
    EXPECT_EQ(expected_priority, logger_data->priority);
    EXPECT_STREQ(LOG_TAG, logger_data->tag);
    EXPECT_STREQ(nullptr, logger_data->file);
    EXPECT_EQ(0U, logger_data->line);
    EXPECT_EQ(expected_message, message);
  };

  __android_log_set_logger(liblog_logger_function);

  __android_log_buf_write(expected_buffer_id, expected_priority, LOG_TAG, expected_message.c_str());
  EXPECT_TRUE(message_seen);
}

TEST(global_state, SetAborter_with_liblog) {
  using namespace android::base;

  std::string expected_message = "libbase test message";
  static bool message_seen = false;
  auto aborter_function = [&](const char* message) {
    message_seen = true;
    EXPECT_EQ(expected_message, message);
  };

  SetAborter(aborter_function);
  LOG(FATAL) << expected_message;
  EXPECT_TRUE(message_seen);
  message_seen = false;

  static std::string expected_message_static = "libbase test message";
  auto liblog_aborter_function = [](const char* message) {
    message_seen = true;
    EXPECT_EQ(expected_message_static, message);
  };
  __android_log_set_aborter(liblog_aborter_function);
  LOG(FATAL) << expected_message_static;
  EXPECT_TRUE(message_seen);
  message_seen = false;
}

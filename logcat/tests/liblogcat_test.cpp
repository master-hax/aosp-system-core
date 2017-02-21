/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <android-base/file.h>
#include <gtest/gtest.h>
#include <log/logcat.h>

#define logcat_define(context) AndroidLogcat context
#define logcat_popen(context, command) context.reset(command).getFp()
#define logcat_pclose(context, fp) context.getRet()
#define logcat_system(command) AndroidLogcat(command).getRet()
#define logcat liblogcat

TEST(liblogcat, api_process) {
    AndroidLogcat logcat("logcat -b all -S");
    ASSERT_EQ(logcat.getRet(), 0);
}

TEST(liblogcat, api_thread) {
    AndroidLogcat logcat("logcat -b all -S");
    ASSERT_NE(logcat.getFp(), static_cast<FILE*>(nullptr));
    std::string content;
    ASSERT_TRUE(android::base::ReadFdToString(fileno(logcat.getFp()), &content));
    ASSERT_EQ(logcat.getRet(), 0);
    ASSERT_NE(content.find("main"), std::string::npos);
}

#include "logcat_test.cpp"

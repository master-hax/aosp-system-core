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

#include <gtest/gtest.h>
#include <log/logcat.h>

#define logcat_define(context) android_logcat_context context
#define logcat_popen(context, command) android_logcat_popen(&(context), command)
#define logcat_pclose(context, fp) android_logcat_pclose(&(context), fp)
#define logcat_system(command) android_logcat_system(command)
#define logcat liblogcat

TEST(liblogcat, ExecuteLogcatCommand) {
    std::string content;

    content = android::ExecuteLogcatCommand("logcat -b all -S 2>&1");
    ASSERT_FALSE(content.empty());
    ASSERT_NE(content.find("main"), std::string::npos)
        << "content=\"" << content << "\"";
    ASSERT_EQ(content.rfind("Error: "), std::string::npos)
        << "content=\"..." << content.substr(content.rfind("ERROR: ")) << "\"";

    content = android::ExecuteLogcatCommand("logcat -b bogusfoo -S 2>&1");
    ASSERT_FALSE(content.empty());
    ASSERT_NE(content.rfind("Error: "), std::string::npos)
        << "content=\"" << content << "\"";
}

#include "logcat_test.cpp"

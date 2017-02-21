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
#define logcat_popen(context, command) (context = command)
#define logcat_pclose(context, fp) context.getRet()
#define logcat_system(command) AndroidLogcat(command).getRet()
#define logcat liblogcat

TEST(liblogcat, api_popen) {
    std::string content;
    android::base::ReadFdToString(fileno(AndroidLogcat("logcat -b all -S")),
                                  &content);
    ASSERT_FALSE(content.empty());
    ASSERT_NE(content.find("main"), std::string::npos);
}

TEST(liblogcat, api_system) {
    ASSERT_EQ(static_cast<int>(AndroidLogcat("logcat -b all -S >/dev/null")), 0);
}

#include "logcat_test.cpp"

/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <stdio.h>

#include <string>

#include <android-base/file.h>
#include <log/logcat.h>

// API has agreed that command and content parameters can be allowed to
// reference same std::string, so do not touch content until after finished
// with command.  Also, by appending error content on command failure with
// stderr redirection to stdout, we ensure that caller can guarantee that
// if there is partial content, they can safely propagate it with embedded
// error details without minding the boolean false return status.  This
// subtlety simplifies error checking in the caller.
bool android::ReadLogcatToString(const std::string& command,
                                 std::string* content) {
    android_logcat_context ctx;
    auto fp = android_logcat_popen(&ctx, command.c_str());
    if (fp == nullptr) {
        content->erase();
        return false;
    }
    auto errorIsRedirected = command.find(" 2>&1") != std::string::npos;
    // finished with command, now pick up content
    auto ret = android::base::ReadFdToString(fileno(fp), content);
    auto retval = android_logcat_pclose(&ctx, fp);
    // if stderr is redirected, report return value ala Android shell behavior
    if (ret && retval && errorIsRedirected) {
        content->append("\n");
        content->append(std::to_string(retval));
        content->append("|");
    }
    return ret && !retval;
}

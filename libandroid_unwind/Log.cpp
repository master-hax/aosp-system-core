/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#include <string>

#define LOG_TAG "unwind"
#include <log/log.h>

#include <android-base/stringprintf.h>

#include "Log.h"

uint8_t g_LoggingIndentLevel = 1;

// Send the data to the log.
void log(const char* format, ...) {
  std::string real_format;
  if (g_LoggingIndentLevel > 0) {
    real_format = android::base::StringPrintf("%*s%s", 2 * g_LoggingIndentLevel, " ", format);
  } else {
    real_format = format;
  }
  va_list args;
  va_start(args, format);
  if (g_LoggingFlags & LOGGING_FLAG_PRINT) {
    real_format += '\n';
    vprintf(real_format.c_str(), args);
  } else {
    LOG_PRI_VA(ANDROID_LOG_INFO, LOG_TAG, real_format.c_str(), args);
  }
  va_end(args);
}

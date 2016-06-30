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

#ifndef _LIBANDROID_UNWIND_LOG_H
#define _LIBANDROID_UNWIND_LOG_H

#include <stdint.h>

enum LoggingFlags : uint16_t {
  LOGGING_FLAG_ENABLE_OP = 0x01,
  LOGGING_FLAG_SKIP_EXECUTION = 0x02,
  LOGGING_FLAG_PRINT = 0x04,
};

constexpr uint16_t g_LoggingFlags = 0
#if defined(LOGGING_ENABLE_OP)
  | LOGGING_FLAG_ENABLE_OP
#endif
#if defined(LOGGING_SKIP_EXECUTION)
  | LOGGING_FLAG_SKIP_EXECUTION
#endif
#if defined(LOGGING_PRINT)
  | LOGGING_FLAG_PRINT
#endif
;
extern uint8_t g_LoggingIndentLevel;

void log(const char* format, ...);

#endif  // _LIBANDROID_UNWIND_LOG_H

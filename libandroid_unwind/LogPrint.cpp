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

#include "Log.h"

// The default when building with this file is to log only to stdout.
bool g_LoggingEnabled = true;
bool g_LoggingOnly = true;
uint8_t g_LoggingIndentLevel = 1;

void log(const char* format, ...) {
  if (g_LoggingIndentLevel) {
    printf("%*s", 2 * g_LoggingIndentLevel, " ");
  }

  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);

  printf("\n");
}

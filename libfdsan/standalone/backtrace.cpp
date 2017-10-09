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

#include "fdsan.h"

#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <mutex>
#include <vector>

#include <async_safe/log.h>
#include <backtrace/Backtrace.h>

struct FdsanBacktrace {
  std::unique_ptr<Backtrace> backtrace;
};

void fdsan_free(FdsanBacktrace* backtrace) {
  delete backtrace;
}

static std::mutex backtrace_mutex;
static std::unique_ptr<BacktraceMap> backtrace_map;

void fdsan_update_map() {
  std::lock_guard<std::mutex> lock(backtrace_mutex);
  backtrace_map.reset(BacktraceMap::Create(getpid()));
}

FdsanBacktrace* fdsan_record_backtrace() {
  std::lock_guard<std::mutex> lock(backtrace_mutex);
  if (!backtrace_map) {
    async_safe_fatal("map not created");
  }

  std::unique_ptr<Backtrace> backtrace(Backtrace::Create(getpid(), gettid(), backtrace_map.get()));
  if (!backtrace) {
    async_safe_fatal("failed to create backtrace");
  }

  // Backtrace::Unwind -> fdsan_record_backtrace -> fdsan_default_reporter -> fdsan_report
  if (!backtrace->Unwind(4)) {
    async_safe_fatal("failed to unwind");
  }

  return new FdsanBacktrace{
      .backtrace = std::move(backtrace),
  };
}

void fdsan_report_backtrace(const FdsanBacktrace* fdsan_backtrace) {
  std::lock_guard<std::mutex> lock(backtrace_mutex);
  if (!fdsan_backtrace) {
    return;
  }

  auto backtrace = fdsan_backtrace->backtrace.get();
  if (!backtrace) {
    async_safe_fatal("missing backtrace");
  }

  for (size_t i = 0; i < backtrace->NumFrames(); ++i) {
    // TODO: This starts with #04...
    std::string formatted = backtrace->FormatFrameData(i);
    async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "    %s", formatted.c_str());
  }
}

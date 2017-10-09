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
#include <atomic>
#include <memory>
#include <mutex>
#include <vector>

#include <async_safe/log.h>
#include <backtrace/Backtrace.h>
#include <unwindstack/Memory.h>

struct FdsanBacktrace {
  std::unique_ptr<Backtrace> backtrace;
};

void fdsan_free(FdsanBacktrace* backtrace) {
  delete backtrace;
}

struct Map {
  bool available;
  size_t generation_number;
  std::unique_ptr<BacktraceMap> map;
};

static std::mutex backtrace_mutex;
static std::condition_variable backtrace_cv;
static std::vector<Map> backtrace_maps;
static std::atomic<size_t> generation_number;

static std::unique_ptr<BacktraceMap> CreateBacktraceMap() {
  std::unique_ptr<BacktraceMap> result(BacktraceMap::Create(getpid()));
  result->GetProcessMemory()->SetUnsafe();
  return result;
}

static std::unique_ptr<Backtrace> CreateBacktrace(BacktraceMap* map) {
  return std::unique_ptr<Backtrace>(Backtrace::Create(getpid(), gettid(), map));
}

static void fdsan_create_maps() {
  for (size_t i = 0; i < 4; ++i) {
    Map map;
    map.available = true;
    map.map = CreateBacktraceMap();
    map.generation_number = generation_number;
    backtrace_maps.emplace_back(std::move(map));
  }
}

static Map& fdsan_get_map() {
  while (true) {
    std::unique_lock<std::mutex> lock(backtrace_mutex);

    if (backtrace_maps.empty()) {
      fdsan_create_maps();
    }

    for (auto& map : backtrace_maps) {
      if (map.available) {
        map.available = false;

        lock.unlock();

        size_t current_generation = generation_number;
        if (map.generation_number != current_generation) {
          map.map = CreateBacktraceMap();
          map.generation_number = current_generation;
        }

        return map;
      }
    }

    backtrace_cv.wait(lock);
  }
}

static void fdsan_return_map(Map& map) {
  {
    std::lock_guard<std::mutex> lock(backtrace_mutex);
    map.available = true;
  }
  backtrace_cv.notify_one();
}

void fdsan_invalidate_maps() {
  ++generation_number;
}

FdsanBacktrace* fdsan_record_backtrace() {
  Map& map = fdsan_get_map();

  auto backtrace = CreateBacktrace(map.map.get());
  if (!backtrace) {
    async_safe_fatal("failed to create backtrace");
  }

  // Backtrace::Unwind -> fdsan_record_backtrace -> fdsan_default_reporter -> fdsan_report
  if (!backtrace->Unwind(4)) {
    async_safe_fatal("failed to unwind");
  }

  fdsan_return_map(map);

  return new FdsanBacktrace{
      .backtrace = std::move(backtrace),
  };
}

void fdsan_report_backtrace(const FdsanBacktrace* fdsan_backtrace) {
  if (!fdsan_backtrace) {
    return;
  }

  auto backtrace = fdsan_backtrace->backtrace.get();
  if (!backtrace) {
    async_safe_fatal("missing backtrace");
  }

  for (size_t i = 0; i < backtrace->NumFrames(); ++i) {
    std::string formatted = backtrace->FormatFrameData(i);
    async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "    %s", formatted.c_str());
  }
}

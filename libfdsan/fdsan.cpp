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

#include <errno.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <mutex>

#include <android-base/thread_annotations.h>
#include <async_safe/log.h>

#include "fdsan_backtrace.h"

static bool fdsan_set_should_record(bool new_value);

struct ScopedDisableRecording {
  ScopedDisableRecording() { previous_ = fdsan_set_should_record(false); }
  ~ScopedDisableRecording() { fdsan_set_should_record(previous_); }

  bool previous_;
};

std::array<Fd, kFdMax> fd_table;

static std::atomic<bool> initialized;
static pthread_key_t record_disabled_key;

bool fdsan_should_record() {
  if (!initialized) {
    return false;
  }

  uintptr_t disabled = reinterpret_cast<uintptr_t>(pthread_getspecific(record_disabled_key));
  return !disabled;
}

bool fdsan_set_should_record(bool new_value) {
  bool previous = fdsan_should_record();
  void* disabled = reinterpret_cast<void*>(!new_value);
  pthread_setspecific(record_disabled_key, disabled);
  return previous;
}

static void __attribute__((constructor)) fdsan_initialize() {
  int rc = 0;

  rc = pthread_key_create(&record_disabled_key, nullptr);
  if (rc != 0) {
    async_safe_fatal("failed to create pthread_key_t: %s", strerror(-rc));
  }

  struct rlimit rlim;
  rc = getrlimit(RLIMIT_NOFILE, &rlim);
  if (rc != 0) {
    async_safe_fatal("getrlimit failed: %s", strerror(errno));
  }

  rlim.rlim_cur = std::min(65536UL, rlim.rlim_cur);
  rlim.rlim_max = std::min(65536UL, rlim.rlim_max);

  rc = setrlimit(RLIMIT_NOFILE, &rlim);
  if (rc != 0) {
    async_safe_fatal("setrlimit failed: %s", strerror(errno));
  }

  initialized = true;
}

int fdsan_record(int fd, FdEvent& event) {
  if (!fdsan_should_record()) {
    return fd;
  }

  ScopedDisableRecording _;
  if (fd == -1) {
    return -1;
  } else if (fd < 0) {
    abort();
  } else if (static_cast<size_t>(fd) > fd_table.size()) {
    abort();
  }

  event.tid = gettid();
  event.backtrace.reset(fdsan_record_backtrace());

  auto& fd_info = fd_table[fd];
  size_t event_id = fd_info.available_event++ % kEventHistoryLength;
  fd_info.events[event_id] = std::move(event);
  return fd;
}

static bool fdsan_report_event(int index, const FdEvent& event) {
  switch (event.type) {
    case FdEventType::None: {
      return false;
    }

    case FdEventType::Open: {
      async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "%d: open on thread %d", index, event.tid);
      break;
    }

    case FdEventType::Socket: {
      async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "%d: socket on thread %d", index, event.tid);
      break;
    }

    case FdEventType::Close: {
      async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "%d: close on thread %d", index, event.tid);
      break;
    }

    case FdEventType::Dup: {
      async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "%d: dup from fd %d on thread %d", index,
                            event.data.dup.from, event.tid);
      break;
    }

    default:
      async_safe_fatal("unhandled FdEventType %d", event.type);
  }

  fdsan_report_backtrace(event.backtrace.get());
  return true;
}

void fdsan_report(const char* function_name, int fd) {
  if constexpr (!kReportMinusOne) {
    if (fd == -1) {
      return;
    }
  }

  ScopedDisableRecording _;

  async_safe_format_log(ANDROID_LOG_ERROR, "fdsan",
                        "ERROR: FdSanitizer: %s called on nonexistent fd %d", function_name, fd);

  async_safe_format_log(ANDROID_LOG_ERROR, "fdsan",
                        "History for fd %d (from oldest to newest):", fd);

  if (fd >= 0 && static_cast<size_t>(fd) < fd_table.size()) {
    std::unique_lock<std::mutex> lock(fd_table[fd].mutex);
    const auto& events = fd_table[fd].events;
    size_t index = fd_table[fd].available_event % kEventHistoryLength;
    auto begin = events.begin() + index;

    int counter = 1;
    for (auto it = begin; it != events.end(); ++it) {
      if (fdsan_report_event(counter, *it)) {
        ++counter;
      }
    }

    if (begin != events.begin()) {
      for (auto it = events.begin(); it != begin; ++it) {
        if (!fdsan_report_event(counter, *it)) {
          async_safe_fatal("empty events in front of ring buffer");
        }

        ++counter;
      }
    }
  }

  async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "current: %s on thread %d", function_name,
                        gettid());
  unique_backtrace backtrace(fdsan_record_backtrace());
  fdsan_report_backtrace(backtrace.get());

  if (kReportFatal) {
    if (!kReportTombstone) {
      signal(SIGABRT, SIG_DFL);
    }
    abort();
  }
}

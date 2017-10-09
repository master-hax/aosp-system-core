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

static bool report_fatal = false;
static bool report_tombstone = false;
static bool report_minus_one = false;

static void fdsan_default_reporter(int fd, const char* function_name, void*);
static FdsanReportFunction fdsan_report_function = fdsan_default_reporter;
static void* fdsan_report_function_arg = nullptr;

int fdsan_configure(FdsanConfigOption option, int value) {
  int original = 0;
  bool* opt = nullptr;
  switch (option) {
    case FdsanConfigOption::ReportFatal:
      opt = &report_fatal;
      break;

    case FdsanConfigOption::ReportTombstone:
      opt = &report_tombstone;
      break;

    case FdsanConfigOption::ReportMinusOne:
      opt = &report_minus_one;
      break;
  }

  original = *opt;
  *opt = value;
  return original;
}

void fdsan_set_reporter(FdsanReportFunction fn, void* arg) {
  fdsan_report_function = fn;
  fdsan_report_function_arg = arg;
}

void fdsan_reset_reporter() {
  fdsan_report_function = fdsan_default_reporter;
  fdsan_report_function_arg = nullptr;
}

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

static int fdsan_record(int fd, FdEvent& event) {
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
  std::lock_guard<std::recursive_mutex> lock(fd_info.mutex);
  size_t event_id = fd_info.available_event++ % kEventHistoryLength;
  fd_info.events[event_id] = std::move(event);
  return fd;
}

int fdsan_record_create(int fd, const char* function) {
  FdEvent event = {};
  event.type = FdEventType::Create;
  event.function = function;
  return fdsan_record(fd, event);
}

int fdsan_record_dup(int fd, const char* function, int from_fd) {
  FdEvent event = {};
  event.type = FdEventType::Dup;
  event.function = function;
  event.data.dup.from = from_fd;
  return fdsan_record(fd, event);
}

int fdsan_record_close(int fd) {
  FdEvent event = {};
  event.type = FdEventType::Close;
  event.function = "close";
  return fdsan_record(fd, event);
}

static bool fdsan_report_event(int index, const FdEvent& event) {
  switch (event.type) {
    case FdEventType::None:
      return false;

    case FdEventType::Create:
    case FdEventType::Close:
      async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "%d: %s on thread %d", index,
                            event.function, event.tid);
      break;

    case FdEventType::Dup:
      async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "%d: dup from fd %d on thread %d", index,
                            event.data.dup.from, event.tid);
      break;

    default:
      async_safe_fatal("unhandled FdEventType %d", event.type);
  }

  if (event.backtrace.get()) {
    fdsan_report_backtrace(event.backtrace.get());
  } else {
    async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "    backtrace missing");
  }
  return true;
}

static bool fd_is_valid(int fd) {
  return fd >= 0 && static_cast<size_t>(fd) < fd_table.size();
}

void fdsan_clear_history(int fd) {
  if (!fd_is_valid(fd)) {
    async_safe_fatal("ERROR: FdSanitizer: attempted to clear history for invalid fd %d", fd);
  }

  std::lock_guard<std::recursive_mutex> lock(fd_table[fd].mutex);
  for (auto& event : fd_table[fd].events) {
    event = FdEvent{};
  }
  fd_table[fd].available_event = 0;
}

void fdsan_iterate_history(int fd, bool (*callback)(int fd, const FdEvent& event, void* arg),
                           void* arg) {
  if (!fd_is_valid(fd)) {
    async_safe_fatal("ERROR: FdSanitizer: attempted to iterate history for invalid fd %d", fd);
  }

  std::lock_guard<std::recursive_mutex> lock(fd_table[fd].mutex);
  const auto& events = fd_table[fd].events;
  size_t index = fd_table[fd].available_event % kEventHistoryLength;
  auto begin = events.begin() + index;

  for (auto it = begin; it != events.end(); ++it) {
    if (it->type == FdEventType::None) {
      continue;
    }

    if (!callback(fd, *it, arg)) {
      return;
    }
  }

  for (auto it = events.begin(); it != begin; ++it) {
    if (it->type == FdEventType::None) {
      continue;
    }

    if (!callback(fd, *it, arg)) {
      return;
    }
  }
}

void fdsan_report(const char* function_name, int fd) {
  if (!report_minus_one) {
    if (fd == -1) {
      return;
    }
  }

  ScopedDisableRecording _;
  fdsan_report_function(fd, function_name, fdsan_report_function_arg);
}

static void fdsan_default_reporter(int fd, const char* function_name, void*) {
  async_safe_format_log(ANDROID_LOG_ERROR, "fdsan",
                        "ERROR: FdSanitizer: %s called on nonexistent fd %d", function_name, fd);

  async_safe_format_log(ANDROID_LOG_ERROR, "fdsan",
                        "History for fd %d (from oldest to newest):", fd);

  if (fd_is_valid(fd)) {
    int counter = 1;
    fdsan_iterate_history(fd,
                          [](int, const FdEvent& event, void* arg) {
                            int* counter = static_cast<int*>(arg);
                            fdsan_report_event((*counter)++, event);
                            return true;
                          },
                          &counter);
  }

  async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "current: %s on thread %d", function_name,
                        gettid());
  unique_backtrace backtrace(fdsan_record_backtrace());
  fdsan_report_backtrace(backtrace.get());

  if (report_fatal) {
    if (!report_tombstone) {
      signal(SIGABRT, SIG_DFL);
    }
    abort();
  }
}

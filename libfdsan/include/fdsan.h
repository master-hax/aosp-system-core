#pragma once

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

#include <stdint.h>
#include <sys/types.h>

#include <array>
#include <mutex>
#include <thread>

#include "fdsan_backtrace.h"

// TODO: Make these configurable at runtime.
static constexpr size_t kStackDepth = 8;
static constexpr size_t kEventHistoryLength = 4;
static constexpr size_t kFdMax = 65536;

enum class FdsanConfigOption {
  // Abort after reporting. Only affects the default reporter.
  // Defaults to false.
  ReportFatal,

  // Generate a tombstone when aborting after reporting. Only affects the default reporter.
  // Defaults to true.
  ReportTombstone,

  // Report when -1 is used as an fd.
  // Defaults to true.
  ReportMinusOne,
};

extern "C" int fdsan_configure(FdsanConfigOption option, int value);

using FdsanReportFunction = void (*)(int fd, const char* function_name, void* arg);
extern "C" void fdsan_set_reporter(FdsanReportFunction fn, void* arg);
extern "C" void fdsan_reset_reporter();

enum class FdEventType {
  None = 0,
  Create,
  Dup,
  Close,
};

struct FdEventCreate {
  // TODO: readlink(/proc/self/fd)?
};

struct FdEventSocket {
  int domain;
  int socket_type;
  int protocol;
};

struct FdEventClose {};

struct FdEventDup {
  int from;
  // TODO: readlink(/proc/self/fd/from)?
};

union FdEventStorage {
  FdEventCreate create;
  FdEventDup dup;
};

struct FdEvent {
  FdEventType type;

  const char* function;
  pid_t tid;
  unique_backtrace backtrace;
  // TODO: timestamp?

  FdEventStorage data;
};

struct Fd {
  std::array<FdEvent, kEventHistoryLength> events;
  std::atomic<size_t> available_event = 0;

  // This mutex is recursive in case a signal is delivered while we have it locked.
  std::recursive_mutex mutex;
};

extern std::array<Fd, kFdMax> fd_table;

// Record an FdEvent.
int fdsan_record_create(int fd, const char* function);
int fdsan_record_dup(int fd, const char* function, int from_fd);
int fdsan_record_close(int fd);

extern "C" void fdsan_clear_history(int fd);
extern "C" void fdsan_iterate_history(int fd,
                                      bool (*callback)(int fd, const FdEvent& event, void* arg),
                                      void* arg);

// Report a failure.
void fdsan_report(const char* function_name, int fd);

template <typename T>
static T fdsan_check_result(const char* function_name, int fd, T rc) {
  if (rc == -1 && errno == EBADF) {
    fdsan_report(function_name, fd);
    return rc;
  } else {
    return rc;
  }
}

#define FDSAN_CHECK_ALWAYS(symbol, fd, ...) \
  fdsan_check_result(#symbol, fd, __real_##symbol(fd, ##__VA_ARGS__))
#define FDSAN_CHECK FDSAN_CHECK_ALWAYS

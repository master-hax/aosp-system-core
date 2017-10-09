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
#include <thread>

#include <android-base/thread_annotations.h>

#include "fdsan_backtrace.h"

// TODO: Make configurable at runtime.
static constexpr size_t kStackDepth = 8;
static constexpr size_t kEventHistoryLength = 4;
static constexpr size_t kFdMax = 65536;

static constexpr bool kReportFatal = false;
static constexpr bool kReportTombstone = true;
static constexpr bool kReportMinusOne = true;

struct FdEvent;
int fdsan_record(int fd, FdEvent& event);
void fdsan_report(const char* function_name, int fd);

enum class FdEventType {
  None,
  Open,
  Socket,
  Close,
  Dup,
};

struct FdEventOpen {
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
  FdEventOpen open;
  FdEventSocket socket;
  FdEventClose close;
  FdEventDup dup;
};

struct FdEvent {
  FdEventType type;

  pid_t tid;
  unique_backtrace backtrace;
  // TODO: timestamp?

  FdEventStorage data;
};

struct Fd {
  std::array<FdEvent, kEventHistoryLength> events GUARDED_BY(mutex);
  size_t available_event GUARDED_BY(mutex) = 0;
  std::mutex mutex;
};

extern std::array<Fd, kFdMax> fd_table;

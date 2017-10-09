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

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <mutex>
#include <shared_mutex>

#include <android/fdsan.h>
#include <async_safe/log.h>

#include <android-base/thread_annotations.h>

#include "fdsan_backtrace.h"
#include "fdsan_wrappers.h"

static bool fdsan_set_should_record(bool new_value);

struct ScopedDisableRecording {
  ScopedDisableRecording() { previous_ = fdsan_set_should_record(false); }
  ~ScopedDisableRecording() { fdsan_set_should_record(previous_); }

  bool previous_;
};

struct FdsanMutex {
  void lock() {
    block_signals();
    pthread_rwlock_rdlock(&fork_mutex);
    pthread_mutex_lock(&mutex_);
  }

  void unlock() {
    pthread_mutex_unlock(&mutex_);
    pthread_rwlock_unlock(&fork_mutex);
    unblock_signals();
  }

 private:
  pthread_mutex_t mutex_ = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
  static pthread_rwlock_t fork_mutex;

  void block_signals() {
    sigset_t sigset;
    sigfillset(&sigset);
    int rc = pthread_sigmask(SIG_SETMASK, &sigset, &old_sigmask);
    if (rc != 0) {
      async_safe_fatal("failed to set signal mask: %s", strerror(rc));
    }
  }

  void unblock_signals() {
    int rc = pthread_sigmask(SIG_SETMASK, &old_sigmask, nullptr);
    if (rc != 0) {
      async_safe_fatal("failed to restore signal mask: %s", strerror(rc));
    }
  }

  sigset_t old_sigmask;

 public:
  static void prefork() {
    pthread_rwlock_wrlock(&fork_mutex);
  }

  static void postfork_parent() {
    pthread_rwlock_unlock(&fork_mutex);
  }

  static void postfork_child() {
    pthread_rwlock_init(&fork_mutex, nullptr);
  }
};

pthread_rwlock_t FdsanMutex::fork_mutex = PTHREAD_RWLOCK_INITIALIZER;

struct Fd {
  std::array<FdEvent, kEventHistoryLength> events;
  size_t available_event = 0;
  FdsanMutex mutex;
};

static auto& fd_table = *new std::array<Fd, kFdMax>();
static std::atomic<bool> initialized;
static pthread_key_t record_disabled_key;

static bool report_fatal = false;
static bool report_tombstone = false;
static bool report_minus_one = false;

static void fdsan_default_error_handler(FdsanError* error, void*);
static FdsanErrorHandler fdsan_error_handler = fdsan_default_error_handler;
static void* fdsan_error_handler_arg = nullptr;

static bool fd_is_valid(int fd) {
  return fd >= 0 && static_cast<size_t>(fd) < fd_table.size();
}

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

void fdsan_set_error_handler(FdsanErrorHandler fn, void* arg) {
  fdsan_error_handler = fn;
  fdsan_error_handler_arg = arg;
}

void fdsan_reset_error_handler() {
  fdsan_error_handler = fdsan_default_error_handler;
  fdsan_error_handler_arg = nullptr;
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

  pthread_atfork(FdsanMutex::prefork, FdsanMutex::postfork_parent, FdsanMutex::postfork_child);

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
  std::lock_guard<FdsanMutex> lock(fd_info.mutex);
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

int fdsan_record_close(int fd, const char* previous_path) {
  FdEvent event = {};
  event.type = FdEventType::Close;
  event.function = "close";
  strncpy(event.data.close.previous, previous_path, sizeof(event.data.close.previous));
  return fdsan_record(fd, event);
}

int fdsan_close(int fd, void* tag) {
  static auto libc_close =
      reinterpret_cast<decltype(&__libc_close_with_tag)>(dlsym(RTLD_NEXT, "__libc_close_with_tag"));

  if (!fdsan_should_record()) {
    return libc_close(fd, tag);
  }

  char buf[PATH_MAX + 1];
  async_safe_format_buffer(buf, sizeof(buf), "/proc/self/fd/%d", fd);
  ssize_t len = readlink(buf, buf, sizeof(buf) - 1);
  if (len == -1) {
    if (errno == ENOENT) {
      strncpy(buf, "<nonexistent>", sizeof(buf));
    } else {
      async_safe_format_buffer(buf, sizeof(buf), "readlink failed: %s", strerror(errno));
    }
  } else {
    buf[len] = '\0';
  }

  auto& fd_info = fd_table[fd];
  std::lock_guard<FdsanMutex> lock(fd_info.mutex);

  int rc = libc_close(fd, tag);
  if (rc == -1) {
    if (errno == EBADF) {
      fdsan_report_use_after_close(fd, "close");
    }
    return -1;
  }
  fdsan_record_close(fd, buf);
  return rc;
}


static bool fdsan_report_event(int index, const FdEvent& event) {
  switch (event.type) {
    case FdEventType::None:
      return false;

    case FdEventType::Create:
      async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "%d: %s on thread %d", index,
                            event.function, event.tid);
      break;

    case FdEventType::Close: {
      char previous[sizeof(event.data.close.previous) + 4];
      strcpy(previous + sizeof(event.data.close.previous), "...");
      strncpy(previous, event.data.close.previous, sizeof(event.data.close.previous));
      async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "%d: close on thread %d (fd was %s)", index,
                            event.tid, previous);
      break;
    }

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

static void fdsan_clear_fd_history(int fd) {
  if (!fd_is_valid(fd)) {
    async_safe_fatal("ERROR: FdSanitizer: attempted to clear history for invalid fd %d", fd);
  }

  std::lock_guard<FdsanMutex> lock(fd_table[fd].mutex);
  for (auto& event : fd_table[fd].events) {
    event = FdEvent{};
  }
  fd_table[fd].available_event = 0;
}

void fdsan_clear_history(int fd) {
  if (fd == -1) {
    for (int i = 0; i < static_cast<int>(fd_table.size()); ++i) {
      fdsan_clear_fd_history(i);
    }
  } else {
    fdsan_clear_fd_history(fd);
  }
}

void fdsan_iterate_history(int fd, bool (*callback)(int fd, const FdEvent& event, void* arg),
                           void* arg) {
  if (!fd_is_valid(fd)) {
    async_safe_fatal("ERROR: FdSanitizer: attempted to iterate history for invalid fd %d", fd);
  }

  std::lock_guard<FdsanMutex> lock(fd_table[fd].mutex);
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

void fdsan_report_use_after_close(int fd, const char* function_name) {
  if (!report_minus_one) {
    if (fd == -1) {
      return;
    }
  }

  ScopedDisableRecording _;
  FdsanError error = {
      .fd = fd,
      .function_name = function_name,
      .details = UseAfterClose{},
  };
  fdsan_error_handler(&error, fdsan_error_handler_arg);
}

void fdsan_report_unowned_close(int fd, void* expected_tag, void* received_tag) {
  if (!report_minus_one) {
    if (fd == -1) {
      return;
    }
  }

  ScopedDisableRecording _;
  FdsanError error = {
      .fd = fd,
      .function_name = "close",
      .details =
          UnownedClose{
              .expected_tag = expected_tag,
              .received_tag = received_tag,
          },
  };
  fdsan_error_handler(&error, fdsan_error_handler_arg);
}

template<typename T>
struct always_false : std::false_type {};

static void fdsan_default_error_handler(FdsanError* error, void*) {
  int fd = error->fd;
  const char* function_name = error->function_name;
  std::visit([&](auto&& arg) {
    using T = std::decay_t<decltype(arg)>;
    if constexpr (std::is_same_v<T, UseAfterClose>) {
      async_safe_format_log(ANDROID_LOG_ERROR, "fdsan",
                            "ERROR: FdSanitizer: %s called on nonexistent fd %d", function_name, fd);
    } else if constexpr (std::is_same_v<T, UnownedClose>) {
      async_safe_format_log(
          ANDROID_LOG_ERROR, "fdsan",
          "ERROR: FdSanitizer: close called with incorrect tag on fd %d (expected %p, received %p)",
          fd, arg.expected_tag, arg.received_tag);
    } else {
      static_assert(always_false<T>::value, "missing case");
    }
  }, error->details);

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

#include "fdsan.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <mutex>

#include <android-base/thread_annotations.h>
#include <async_safe/log.h>

#include "fdsan_wrappers.h"

static bool fdsan_set_should_record(bool new_value);

struct ScopedDisableRecording {
  ScopedDisableRecording() { previous_ = fdsan_set_should_record(false); }
  ~ScopedDisableRecording() { fdsan_set_should_record(previous_); }

  bool previous_;
};

struct Fd {
  std::array<FdEvent, kEventHistoryLength> events GUARDED_BY(mutex);
  size_t available_event GUARDED_BY(mutex) = 0;
  std::mutex mutex;
};

static std::atomic<bool> initialized;
static pthread_key_t record_disabled_key;
static std::array<Fd, kFdMax> fd_table;

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

  event.backtrace.reset(fdsan_record_backtrace());

  auto& fd_info = fd_table[fd];
  size_t event_id = fd_info.available_event++ % kEventHistoryLength;
  fd_info.events[event_id] = std::move(event);
  return fd;
}

// Record that a file descriptor has been opened.
static int fdsan_open(int fd) {
  FdEvent event = {};
  event.type = FdEventType::Open;
  return fdsan_record(fd, event);
}

static int fdsan_socket(int fd, int domain, int type, int protocol) {
  FdEvent event = {};
  event.type = FdEventType::Socket;
  event.data.socket.domain = domain;
  event.data.socket.socket_type = type;
  event.data.socket.protocol = protocol;
  return fdsan_record(fd, event);
}

static int fdsan_dup(int oldfd, int newfd) {
  FdEvent event = {};
  event.type = FdEventType::Dup;
  event.data.dup.from = oldfd;
  return fdsan_record(newfd, event);
}

// TODO: Make this configurable.
static bool fdsan_report_event(int index, const FdEvent& event) {
  switch (event.type) {
    case FdEventType::None: {
      return false;
    }

    case FdEventType::Open: {
      async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "%d: open", index);
      break;
    }

    case FdEventType::Socket: {
      async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "%d: socket", index);
      break;
    }

    case FdEventType::Close: {
      async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "%d: close", index);
      break;
    }

    case FdEventType::Dup: {
      async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "%d: dup from fd %d", index,
                            event.data.dup.from);
      break;
    }

    default:
      async_safe_fatal("unhandled FdEventType %d", event.type);
  }

  fdsan_report_backtrace(event.backtrace.get());
  return true;
}

static void fdsan_report(const char* function_name, int fd) {
  ScopedDisableRecording _;

  async_safe_format_log(ANDROID_LOG_ERROR, "fdsan",
                        "ERROR: FdSanitizer: %s called on nonexistent fd %d", function_name, fd);

  async_safe_format_log(ANDROID_LOG_ERROR, "fdsan",
                        "History for fd %d (from oldest to newest):", fd);

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

  async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "current: %s", function_name);
  unique_backtrace backtrace(fdsan_record_backtrace());
  fdsan_report_backtrace(backtrace.get());

  // TODO: Make this configurable.
  signal(SIGABRT, SIG_DFL);
  abort();
}

template <typename T>
static T fdsan_check_result(const char* function_name, int fd, T rc) {
  if (rc == -1 && errno == EBADF) {
    fdsan_report(function_name, fd);
    return rc;
  } else {
    return rc;
  }
}

#define FDSAN_CHECK(symbol, fd, ...) \
  fdsan_check_result(#symbol, fd, __real_##symbol(fd, ##__VA_ARGS__))

extern "C" int dup(int fd) {
  int rc = FDSAN_CHECK(dup, fd);
  return fdsan_open(rc);
}

extern "C" int dup3(int oldfd, int newfd, int flags) {
  int rc = FDSAN_CHECK(dup3, oldfd, newfd, flags);
  return fdsan_dup(oldfd, rc);
}

extern "C" int dup2(int oldfd, int newfd) {
  int rc = FDSAN_CHECK(dup3, oldfd, newfd, 0);
  return fdsan_dup(oldfd, rc);
}

extern "C" int fcntl(int fd, int cmd, ...) {
  // This is bit sketchy, but this works on all of our ABIs, because on 32-bit, int is the same size
  // as void*, and all of our 64-bit ABIs will pass the arg in a register.
  va_list args;
  va_start(args, cmd);
  void* arg = va_arg(args, void*);
  va_end(args);

  int rc = FDSAN_CHECK(fcntl, fd, cmd, arg);
  if (cmd == F_DUPFD) {
    return fdsan_dup(fd, rc);
  }

  return rc;
}

extern "C" int open(const char* pathname, int flags, ...) {
  va_list args;
  va_start(args, flags);
  mode_t mode = static_cast<int>(va_arg(args, int));
  va_end(args);
  return fdsan_open(__real_open(pathname, flags, mode));
}

extern "C" int socket(int domain, int type, int protocol) {
  int rc = FDSAN_CHECK(socket, domain, type, protocol);
  return fdsan_socket(rc, domain, type, protocol);
}

extern "C" int close(int fd) {
  int rc = FDSAN_CHECK(close, fd);

  if (rc == -1 && errno == EBADF) {
    fdsan_report(__FUNCTION__, fd);
    return -1;
  }

  if (fd >= 0 && static_cast<size_t>(fd) < fd_table.size()) {
    FdEvent event;
    event.type = FdEventType::Close;
    fdsan_record(fd, event);
  }

  return rc;
}

#pragma once

#include <stdint.h>

#include <memory>

// TODO: Make configurable at runtime.
static constexpr size_t kStackDepth = 8;
static constexpr size_t kEventHistoryLength = 4;
static constexpr size_t kFdMax = 65536;

struct FdsanBacktrace;

extern "C" void fdsan_free(FdsanBacktrace*);
extern "C" FdsanBacktrace* fdsan_record_backtrace();
extern "C" void fdsan_report_backtrace(const FdsanBacktrace*);

struct unique_backtrace {
  unique_backtrace(FdsanBacktrace* ptr = nullptr) : ptr_(ptr) {}
  ~unique_backtrace() { reset(); }

  unique_backtrace(const unique_backtrace& copy) = delete;
  unique_backtrace(unique_backtrace&& move) { reset(move.release()); }

  unique_backtrace& operator=(const unique_backtrace& copy) = delete;
  unique_backtrace& operator=(unique_backtrace&& move) {
    reset(move.release());
    return *this;
  }

  void reset(FdsanBacktrace* ptr = nullptr) {
    if (ptr_) {
      fdsan_free(ptr_);
    }
    ptr_ = ptr;
  }

  FdsanBacktrace* release() {
    FdsanBacktrace* result = ptr_;
    ptr_ = nullptr;
    return result;
  }

  FdsanBacktrace* get() { return ptr_; }
  const FdsanBacktrace* get() const { return ptr_; }

 private:
  FdsanBacktrace* ptr_;
};

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
  unique_backtrace backtrace;
  // TODO: timestamp?

  FdEventStorage data;
};

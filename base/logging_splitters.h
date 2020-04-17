#include <mutex>

#include <android-base/logging.h>

#define LOGGER_ENTRY_MAX_PAYLOAD 4068  // This constant is not in the NDK.

namespace android {
namespace base {

template <typename F>
static void SplitByLines(LogId log_id, LogSeverity severity, const char* tag, const char* file,
                         unsigned int line, const char* msg, const F& log_function,
                         std::mutex* lock) {
  std::unique_lock<std::mutex> guard;
  if (lock != nullptr) {
    guard = std::unique_lock<std::mutex>{*lock};
  }

  const char* newline = strchr(msg, '\n');
  while (newline != nullptr) {
    log_function(log_id, severity, tag, file, line, msg, newline - msg);
    msg = newline + 1;
    newline = strchr(msg, '\n');
  }

  log_function(log_id, severity, tag, file, line, msg, -1);
}

template <typename F>
static void SplitByLogdLines(LogId log_id, LogSeverity severity, const char* tag, const char* file,
                             unsigned int line, const char* msg, const F& log_function,
                             std::mutex* lock) {
  std::unique_lock<std::mutex> guard;
  if (lock != nullptr) {
    guard = std::unique_lock<std::mutex>{*lock};
  }

  // The maximum size of a payload, after the log header that logd will accept is
  // LOGGER_ENTRY_MAX_PAYLOAD, so subtract the other elements in the payload to find the size of
  // the string that we can log in each pass.
  // The protocol is documented in liblog/README.protocol.md.
  // Specifically we subtract a byte for the priority, the length of the tag + its null terminator,
  // and an additional byte for the null terminator on the payload.  We subtract an additional 32
  // bytes for slack, similar to java/android/util/Log.java.
  ptrdiff_t max_size = LOGGER_ENTRY_MAX_PAYLOAD - strlen(tag) - 35;
  // If we're logging a fatal message, we'll append the file and line numbers.
  if (file != nullptr && (severity == FATAL || severity == FATAL_WITHOUT_ABORT)) {
    max_size -= strlen(file);
    max_size -= 13;  // 10 bytes is the max uint length, plus a ':', ']' and ' ';
  }

  const char* previous_newline = nullptr;
  const char* newline = strchr(msg, '\n');
  while (newline != nullptr) {
    if (newline - msg > max_size) {
      if (previous_newline == nullptr) {
        // Trying to log a very long line, log_function will truncate.
        log_function(log_id, severity, tag, file, line, msg, newline - msg);
        msg = newline + 1;
      } else {
        // Log up to the previous newline then continue.
        log_function(log_id, severity, tag, file, line, msg, previous_newline - msg);
        msg = previous_newline + 1;
      }
      previous_newline = nullptr;
      newline = strchr(msg, '\n');
      continue;
    }

    if (newline - msg == max_size) {
      log_function(log_id, severity, tag, file, line, msg, newline - msg);
      msg = newline + 1;
      previous_newline = nullptr;
      newline = strchr(msg, '\n');
      continue;
    }

    previous_newline = newline;
    newline = strchr(newline + 1, '\n');
  }

  log_function(log_id, severity, tag, file, line, msg, -1);
}

}  // namespace base
}  // namespace android

/*
 * Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include <inttypes.h>

#include <mutex>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>

#define LOGGER_ENTRY_MAX_PAYLOAD 4068  // This constant is not in the NDK.

namespace android {
namespace base {

// This splits the message up line by line, by calling log_function with a pointer to the start of
// each line and the size up to the newline character.  It sends size = -1 for the final line.
template <typename F, typename... Args>
static void SplitByLines(const char* msg, const F& log_function, std::mutex* lock, Args&&... args) {
  std::unique_lock<std::mutex> guard;
  if (lock != nullptr) {
    guard = std::unique_lock<std::mutex>{*lock};
  }

  const char* newline = strchr(msg, '\n');
  while (newline != nullptr) {
    log_function(msg, newline - msg, args...);
    msg = newline + 1;
    newline = strchr(msg, '\n');
  }

  log_function(msg, -1, args...);
}

// This splits the message up into chunks that logs can process delimited by new lines.  It calls
// log_function with a pointer to the start of each chunk and the size up to the final character
// that should be sent to logd.  It sends size = -1 for the final chunk.
template <typename F>
static void SplitByLogdChunks(LogId log_id, LogSeverity severity, const char* tag, const char* file,
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

static std::pair<int, int> CountSizeAndNewLines(const char* message) {
  int size = 0;
  int new_lines = 0;
  while (*message != '\0') {
    size++;
    if (*message == '\n') {
      ++new_lines;
    }
    ++message;
  }
  return {size, new_lines};
}

// This adds the log header to each line of message and returns it as a string intended to be
// written to stderr.
static std::string StderrOutputGenerator(const struct tm& now, int pid, uint64_t tid,
                                         LogSeverity severity, const char* tag, const char* file,
                                         unsigned int line, const char* message) {
  char timestamp[32];
  strftime(timestamp, sizeof(timestamp), "%m-%d %H:%M:%S", &now);

  static const char log_characters[] = "VDIWEFF";
  static_assert(arraysize(log_characters) - 1 == FATAL + 1,
                "Mismatch in size of log_characters and values in LogSeverity");
  char severity_char = log_characters[severity];
  std::string line_prefix;
  if (file != nullptr) {
    line_prefix = StringPrintf("%s %c %s %5d %5" PRIu64 " %s:%u] ", tag ? tag : "nullptr",
                               severity_char, timestamp, pid, tid, file, line);
  } else {
    line_prefix = StringPrintf("%s %c %s %5d %5" PRIu64 " ", tag ? tag : "nullptr", severity_char,
                               timestamp, pid, tid);
  }

  auto [size, new_lines] = CountSizeAndNewLines(message);
  std::string output_string;
  output_string.reserve(size + new_lines * line_prefix.size() + 1);

  auto concat_lines = [&](const char* message, int size) {
    output_string.append(line_prefix);
    if (size == -1) {
      output_string.append(message);
    } else {
      output_string.append(message, size);
    }
    output_string.append("\n");
  };
  SplitByLines(message, concat_lines, nullptr);
  return output_string;
}

}  // namespace base
}  // namespace android

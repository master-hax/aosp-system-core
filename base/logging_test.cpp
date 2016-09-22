/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "android-base/logging.h"

#include <libgen.h>

#if defined(_WIN32)
#include <signal.h>
#endif

#include <regex>
#include <string>

#include "android-base/file.h"
#include "android-base/stringprintf.h"
#include "android-base/test_utils.h"

#include <gtest/gtest.h>

#ifdef __ANDROID__
#define HOST_TEST(suite, name) TEST(suite, DISABLED_ ## name)
#else
#define HOST_TEST(suite, name) TEST(suite, name)
#endif

class CapturedStderr {
 public:
  CapturedStderr() : old_stderr_(-1) {
    init();
  }

  ~CapturedStderr() {
    reset();
  }

  int fd() const {
    return temp_file_.fd;
  }

 private:
  void init() {
#if defined(_WIN32)
    // On Windows, stderr is often buffered, so make sure it is unbuffered so
    // that we can immediately read back what was written to stderr.
    ASSERT_EQ(0, setvbuf(stderr, NULL, _IONBF, 0));
#endif
    old_stderr_ = dup(STDERR_FILENO);
    ASSERT_NE(-1, old_stderr_);
    ASSERT_NE(-1, dup2(fd(), STDERR_FILENO));
  }

  void reset() {
    ASSERT_NE(-1, dup2(old_stderr_, STDERR_FILENO));
    ASSERT_EQ(0, close(old_stderr_));
    // Note: cannot restore prior setvbuf() setting.
  }

  TemporaryFile temp_file_;
  int old_stderr_;
};

#if defined(_WIN32)
static void ExitSignalAbortHandler(int) {
  _exit(3);
}
#endif

static void SuppressAbortUI() {
#if defined(_WIN32)
  // We really just want to call _set_abort_behavior(0, _CALL_REPORTFAULT) to
  // suppress the Windows Error Reporting dialog box, but that API is not
  // available in the OS-supplied C Runtime, msvcrt.dll, that we currently
  // use (it is available in the Visual Studio C runtime).
  //
  // Instead, we setup a SIGABRT handler, which is called in abort() right
  // before calling Windows Error Reporting. In the handler, we exit the
  // process just like abort() does.
  ASSERT_NE(SIG_ERR, signal(SIGABRT, ExitSignalAbortHandler));
#endif
}

TEST(logging, CHECK) {
  ASSERT_DEATH({SuppressAbortUI(); CHECK(false);}, "Check failed: false ");
  CHECK(true);

  ASSERT_DEATH({SuppressAbortUI(); CHECK_EQ(0, 1);}, "Check failed: 0 == 1 ");
  CHECK_EQ(0, 0);

  ASSERT_DEATH({SuppressAbortUI(); CHECK_STREQ("foo", "bar");},
               R"(Check failed: "foo" == "bar")");
  CHECK_STREQ("foo", "foo");

  // Test whether CHECK() and CHECK_STREQ() have a dangling if with no else.
  bool flag = false;
  if (true)
    CHECK(true);
  else
    flag = true;
  EXPECT_FALSE(flag) << "CHECK macro probably has a dangling if with no else";

  flag = false;
  if (true)
    CHECK_STREQ("foo", "foo");
  else
    flag = true;
  EXPECT_FALSE(flag) << "CHECK_STREQ probably has a dangling if with no else";
}

TEST(logging, DCHECK) {
  if (android::base::kEnableDChecks) {
    ASSERT_DEATH({SuppressAbortUI(); DCHECK(false);}, "DCheck failed: false ");
  }
  DCHECK(true);

  if (android::base::kEnableDChecks) {
    ASSERT_DEATH({SuppressAbortUI(); DCHECK_EQ(0, 1);}, "DCheck failed: 0 == 1 ");
  }
  DCHECK_EQ(0, 0);

  if (android::base::kEnableDChecks) {
    ASSERT_DEATH({SuppressAbortUI(); DCHECK_STREQ("foo", "bar");},
                 R"(DCheck failed: "foo" == "bar")");
  }
  DCHECK_STREQ("foo", "foo");

  // No testing whether we have a dangling else, possibly. That's inherent to the if (constexpr)
  // setup we intentionally chose to force type-checks of debug code even in release builds (so
  // we don't get more bit-rot).
}

#define CHECK_WOULD_LOG_DISABLED(severity)                                             \
  static_assert(android::base::severity < android::base::FATAL, "Bad input");          \
  for (size_t i = static_cast<size_t>(android::base::severity) + 1;                    \
       i <= static_cast<size_t>(android::base::FATAL);                                 \
       ++i) {                                                                          \
    android::base::ScopedLogSeverity sls2(static_cast<android::base::LogSeverity>(i)); \
    EXPECT_FALSE(WOULD_LOG(severity)) << i;                                            \
  }

#define CHECK_WOULD_LOG_ENABLED(severity)                                              \
  for (size_t i = static_cast<size_t>(android::base::VERBOSE);                         \
       i <= static_cast<size_t>(android::base::severity);                              \
       ++i) {                                                                          \
    android::base::ScopedLogSeverity sls2(static_cast<android::base::LogSeverity>(i)); \
    EXPECT_TRUE(WOULD_LOG(severity)) << i;                                             \
  }

TEST(logging, WOULD_LOG_FATAL) {
  CHECK_WOULD_LOG_ENABLED(FATAL);
}

TEST(logging, WOULD_LOG_FATAL_WITHOUT_ABORT_disabled) {
  CHECK_WOULD_LOG_DISABLED(FATAL_WITHOUT_ABORT);
}

TEST(logging, WOULD_LOG_FATAL_WITHOUT_ABORT_enabled) {
  CHECK_WOULD_LOG_ENABLED(FATAL_WITHOUT_ABORT);
}

TEST(logging, WOULD_LOG_ERROR_disabled) {
  CHECK_WOULD_LOG_DISABLED(ERROR);
}

TEST(logging, WOULD_LOG_ERROR_enabled) {
  CHECK_WOULD_LOG_ENABLED(ERROR);
}

TEST(logging, WOULD_LOG_WARNING_disabled) {
  CHECK_WOULD_LOG_DISABLED(WARNING);
}

TEST(logging, WOULD_LOG_WARNING_enabled) {
  CHECK_WOULD_LOG_ENABLED(WARNING);
}

TEST(logging, WOULD_LOG_INFO_disabled) {
  CHECK_WOULD_LOG_DISABLED(INFO);
}

TEST(logging, WOULD_LOG_INFO_enabled) {
  CHECK_WOULD_LOG_ENABLED(INFO);
}

TEST(logging, WOULD_LOG_DEBUG_disabled) {
  CHECK_WOULD_LOG_DISABLED(DEBUG);
}

TEST(logging, WOULD_LOG_DEBUG_enabled) {
  CHECK_WOULD_LOG_ENABLED(DEBUG);
}

TEST(logging, WOULD_LOG_VERBOSE_disabled) {
  CHECK_WOULD_LOG_DISABLED(VERBOSE);
}

TEST(logging, WOULD_LOG_VERBOSE_enabled) {
  CHECK_WOULD_LOG_ENABLED(VERBOSE);
}

#undef CHECK_WOULD_LOG_DISABLED
#undef CHECK_WOULD_LOG_ENABLED


#define CHECK_WOULD_LOG_SEVERITY_DISABLED(severity)                                    \
  static_assert(android::base::severity < android::base::FATAL, "Bad input");          \
  for (size_t i = static_cast<size_t>(android::base::severity) + 1;                    \
       i <= static_cast<size_t>(android::base::FATAL);                                 \
       ++i) {                                                                          \
    android::base::ScopedLogSeverity sls2(static_cast<android::base::LogSeverity>(i)); \
    EXPECT_FALSE(WOULD_LOG_SEVERITY(::android::base::severity)) << i;                  \
  }

#define CHECK_WOULD_LOG_SEVERITY_ENABLED(severity)                                     \
  for (size_t i = static_cast<size_t>(android::base::VERBOSE);                         \
       i <= static_cast<size_t>(android::base::severity);                              \
       ++i) {                                                                          \
    android::base::ScopedLogSeverity sls2(static_cast<android::base::LogSeverity>(i)); \
    EXPECT_TRUE(WOULD_LOG_SEVERITY(::android::base::severity)) << i;                   \
  }

TEST(logging,WOULD_LOG_SEVERITY_FATAL) {
  CHECK_WOULD_LOG_SEVERITY_ENABLED(FATAL);
}

TEST(logging,WOULD_LOG_SEVERITY_FATAL_WITHOUT_ABORT_disabled) {
  CHECK_WOULD_LOG_SEVERITY_DISABLED(FATAL_WITHOUT_ABORT);
}

TEST(logging, WOULD_LOG_SEVERITY_FATAL_WITHOUT_ABORT_enabled) {
  CHECK_WOULD_LOG_SEVERITY_ENABLED(FATAL_WITHOUT_ABORT);
}

TEST(logging, WOULD_LOG_SEVERITY_ERROR_disabled) {
  CHECK_WOULD_LOG_SEVERITY_DISABLED(ERROR);
}

TEST(logging, WOULD_LOG_SEVERITY_ERROR_enabled) {
  CHECK_WOULD_LOG_SEVERITY_ENABLED(ERROR);
}

TEST(logging, WOULD_LOG_SEVERITY_WARNING_disabled) {
  CHECK_WOULD_LOG_SEVERITY_DISABLED(WARNING);
}

TEST(logging, WOULD_LOG_SEVERITY_WARNING_enabled) {
  CHECK_WOULD_LOG_SEVERITY_ENABLED(WARNING);
}

TEST(logging, WOULD_LOG_SEVERITY_INFO_disabled) {
  CHECK_WOULD_LOG_SEVERITY_DISABLED(INFO);
}

TEST(logging, WOULD_LOG_SEVERITY_INFO_enabled) {
  CHECK_WOULD_LOG_SEVERITY_ENABLED(INFO);
}

TEST(logging, WOULD_LOG_SEVERITY_DEBUG_disabled) {
  CHECK_WOULD_LOG_SEVERITY_DISABLED(DEBUG);
}

TEST(logging, WOULD_LOG_SEVERITY_DEBUG_enabled) {
  CHECK_WOULD_LOG_SEVERITY_ENABLED(DEBUG);
}

TEST(logging, WOULD_LOG_SEVERITYVERBOSE_disabled) {
  CHECK_WOULD_LOG_SEVERITY_DISABLED(VERBOSE);
}

TEST(logging, WOULD_LOG_SEVERITY_VERBOSE_enabled) {
  CHECK_WOULD_LOG_SEVERITY_ENABLED(VERBOSE);
}

#undef CHECK_WOULD_LOG_SEVERITY_DISABLED
#undef CHECK_WOULD_LOG_SEVERITY_ENABLED

static std::string make_log_pattern(android::base::LogSeverity severity,
                                    const char* message) {
  static const char log_characters[] = "VDIWEFF";
  static_assert(arraysize(log_characters) - 1 == android::base::FATAL + 1,
                "Mismatch in size of log_characters and values in LogSeverity");
  char log_char = log_characters[severity];
  std::string holder(__FILE__);
  return android::base::StringPrintf(
      "%c \\d+-\\d+ \\d+:\\d+:\\d+ \\s*\\d+ \\s*\\d+ %s:\\d+] %s",
      log_char, basename(&holder[0]), message);
}

static void CheckMessage(const CapturedStderr& cap,
                         android::base::LogSeverity severity, const char* expected) {
  std::string output;
  ASSERT_EQ(0, lseek(cap.fd(), 0, SEEK_SET));
  android::base::ReadFdToString(cap.fd(), &output);

  // We can't usefully check the output of any of these on Windows because we
  // don't have std::regex, but we can at least make sure we printed at least as
  // many characters are in the log message.
  ASSERT_GT(output.length(), strlen(expected));
  ASSERT_NE(nullptr, strstr(output.c_str(), expected)) << output;

#if !defined(_WIN32)
  std::regex message_regex(make_log_pattern(severity, expected));
  ASSERT_TRUE(std::regex_search(output, message_regex)) << output;
#endif
}

#define CHECK_LOG_STREAM(severity) \
  android::base::ScopedLogSeverity sls2(android::base::severity); \
  CapturedStderr cap2; \
  LOG_STREAM(severity) << "foobar"; \
  CheckMessage(cap2, android::base::severity, "foobar"); \

TEST(logging, LOG_STREAM_FATAL_WITHOUT_ABORT) {
  CHECK_LOG_STREAM(FATAL_WITHOUT_ABORT);
}

TEST(logging, LOG_STREAM_ERROR) {
  CHECK_LOG_STREAM(ERROR);
}

TEST(logging, LOG_STREAM_WARNING) {
  CHECK_LOG_STREAM(WARNING);
}

TEST(logging, LOG_STREAM_INFO) {
  CHECK_LOG_STREAM(INFO);
}

TEST(logging, LOG_STREAM_DEBUG) {
  CHECK_LOG_STREAM(DEBUG);
}

TEST(logging, LOG_STREAM_VERBOSE) {
  CHECK_LOG_STREAM(VERBOSE);
}

#undef CHECK_LOG_STREAM

#define CHECK_LOG_S_STREAM(severity) \
  android::base::ScopedLogSeverity sls2(android::base::severity); \
  CapturedStderr cap2; \
  LOG_S_STREAM(android::base::severity) << "foobar"; \
  CheckMessage(cap2, android::base::severity, "foobar"); \

TEST(logging, LOG_S_STREAM_FATAL_WITHOUT_ABORT) {
  CHECK_LOG_S_STREAM(FATAL_WITHOUT_ABORT);
}

TEST(logging, LOG_S_STREAM_ERROR) {
  CHECK_LOG_S_STREAM(ERROR);
}

TEST(logging, LOG_S_STREAM_WARNING) {
  CHECK_LOG_S_STREAM(WARNING);
}

TEST(logging, LOG_S_STREAM_INFO) {
  CHECK_LOG_S_STREAM(INFO);
}

TEST(logging, LOG_S_STREAM_DEBUG) {
  CHECK_LOG_S_STREAM(DEBUG);
}

TEST(logging, LOG_S_STREAM_VERBOSE) {
  CHECK_LOG_S_STREAM(VERBOSE);
}

#undef CHECK_LOG_S_STREAM


#define CHECK_LOG_DISABLED(severity) \
  android::base::ScopedLogSeverity sls1(android::base::FATAL); \
  CapturedStderr cap1; \
  LOG(severity) << "foo bar"; \
  ASSERT_EQ(0, lseek(cap1.fd(), 0, SEEK_CUR)); \

#define CHECK_LOG_ENABLED(severity) \
  android::base::ScopedLogSeverity sls2(android::base::severity); \
  CapturedStderr cap2; \
  LOG(severity) << "foobar"; \
  CheckMessage(cap2, android::base::severity, "foobar"); \

TEST(logging, LOG_FATAL) {
  ASSERT_DEATH({SuppressAbortUI(); LOG(FATAL) << "foobar";}, "foobar");
}

TEST(logging, LOG_FATAL_WITHOUT_ABORT_disabled) {
  CHECK_LOG_DISABLED(FATAL_WITHOUT_ABORT);
}

TEST(logging, LOG_FATAL_WITHOUT_ABORT_enabled) {
  CHECK_LOG_ENABLED(FATAL_WITHOUT_ABORT);
}

TEST(logging, LOG_ERROR_disabled) {
  CHECK_LOG_DISABLED(ERROR);
}

TEST(logging, LOG_ERROR_enabled) {
  CHECK_LOG_ENABLED(ERROR);
}

TEST(logging, LOG_WARNING_disabled) {
  CHECK_LOG_DISABLED(WARNING);
}

TEST(logging, LOG_WARNING_enabled) {
  CHECK_LOG_ENABLED(WARNING);
}

TEST(logging, LOG_INFO_disabled) {
  CHECK_LOG_DISABLED(INFO);
}

TEST(logging, LOG_INFO_enabled) {
  CHECK_LOG_ENABLED(INFO);
}

TEST(logging, LOG_DEBUG_disabled) {
  CHECK_LOG_DISABLED(DEBUG);
}

TEST(logging, LOG_DEBUG_enabled) {
  CHECK_LOG_ENABLED(DEBUG);
}

TEST(logging, LOG_VERBOSE_disabled) {
  CHECK_LOG_DISABLED(VERBOSE);
}

TEST(logging, LOG_VERBOSE_enabled) {
  CHECK_LOG_ENABLED(VERBOSE);
}

#undef CHECK_LOG_DISABLED
#undef CHECK_LOG_ENABLED

#define CHECK_LOG_S_DISABLED(severity) \
  android::base::ScopedLogSeverity sls1(android::base::FATAL); \
  CapturedStderr cap1; \
  LOG_S(::android::base::severity) << "foo bar"; \
  ASSERT_EQ(0, lseek(cap1.fd(), 0, SEEK_CUR)); \

#define CHECK_LOG_S_ENABLED(severity) \
  android::base::ScopedLogSeverity sls2(android::base::severity); \
  CapturedStderr cap2; \
  LOG_S(::android::base::severity) << "foobar"; \
  CheckMessage(cap2, android::base::severity, "foobar"); \

TEST(logging, LOG_S_FATAL) {
  ASSERT_DEATH({SuppressAbortUI(); LOG_S(::android::base::FATAL) << "foobar";}, "foobar");
}

TEST(logging, LOG_S_FATAL_WITHOUT_ABORT_disabled) {
  CHECK_LOG_S_DISABLED(FATAL_WITHOUT_ABORT);
}

TEST(logging, LOG_S_FATAL_WITHOUT_ABORT_enabled) {
  CHECK_LOG_S_ENABLED(FATAL_WITHOUT_ABORT);
}

TEST(logging, LOG_S_ERROR_disabled) {
  CHECK_LOG_S_DISABLED(ERROR);
}

TEST(logging, LOG_S_ERROR_enabled) {
  CHECK_LOG_S_ENABLED(ERROR);
}

TEST(logging, LOG_S_WARNING_disabled) {
  CHECK_LOG_S_DISABLED(WARNING);
}

TEST(logging, LOG_S_WARNING_enabled) {
  CHECK_LOG_S_ENABLED(WARNING);
}

TEST(logging, LOG_S_INFO_disabled) {
  CHECK_LOG_S_DISABLED(INFO);
}

TEST(logging, LOG_S_INFO_enabled) {
  CHECK_LOG_S_ENABLED(INFO);
}

TEST(logging, LOG_S_DEBUG_disabled) {
  CHECK_LOG_S_DISABLED(DEBUG);
}

TEST(logging, LOG_S_DEBUG_enabled) {
  CHECK_LOG_S_ENABLED(DEBUG);
}

TEST(logging, LOG_S_VERBOSE_disabled) {
  CHECK_LOG_S_DISABLED(VERBOSE);
}

TEST(logging, LOG_S_VERBOSE_enabled) {
  CHECK_LOG_S_ENABLED(VERBOSE);
}

#undef CHECK_LOG_S_DISABLED
#undef CHECK_LOG_S_ENABLED

TEST(logging, LOG_S_complex_param) {
#define CHECK_LOG_S_COMBINATION(use_scoped_log_severity_info, use_logging_severity_info)           \
  {                                                                                                \
    android::base::ScopedLogSeverity sls(                                                          \
        (use_scoped_log_severity_info) ? ::android::base::INFO : ::android::base::WARNING);        \
    CapturedStderr cap;                                                                            \
    LOG_S((use_logging_severity_info) ? ::android::base::INFO : ::android::base::WARNING)          \
        << "foobar";                                                                               \
    if ((use_scoped_log_severity_info) || !(use_logging_severity_info)) {                          \
      CheckMessage(cap,                                                                            \
                   (use_logging_severity_info) ? ::android::base::INFO : ::android::base::WARNING, \
                   "foobar");                                                                      \
    } else {                                                                                       \
      ASSERT_EQ(0, lseek(cap.fd(), 0, SEEK_CUR));                                                  \
    }                                                                                              \
  }

  CHECK_LOG_S_COMBINATION(false,false);
  CHECK_LOG_S_COMBINATION(false,true);
  CHECK_LOG_S_COMBINATION(true,false);
  CHECK_LOG_S_COMBINATION(true,true);

#undef CHECK_LOG_S_COMBINATION
}


TEST(logging, LOG_does_not_clobber_errno) {
  CapturedStderr cap;
  errno = 12345;
  LOG(INFO) << (errno = 67890);
  EXPECT_EQ(12345, errno) << "errno was not restored";

  CheckMessage(cap, android::base::INFO, "67890");
}

TEST(logging, LOG_S_does_not_clobber_errno) {
  CapturedStderr cap;
  errno = 12345;
  LOG_S(::android::base::INFO) << (errno = 67890);
  EXPECT_EQ(12345, errno) << "errno was not restored";

  CheckMessage(cap, android::base::INFO, "67890");
}

TEST(logging, PLOG_does_not_clobber_errno) {
  CapturedStderr cap;
  errno = 12345;
  PLOG(INFO) << (errno = 67890);
  EXPECT_EQ(12345, errno) << "errno was not restored";

  CheckMessage(cap, android::base::INFO, "67890");
}

TEST(logging, PLOG_S_does_not_clobber_errno) {
  CapturedStderr cap;
  errno = 12345;
  PLOG_S(::android::base::INFO) << (errno = 67890);
  EXPECT_EQ(12345, errno) << "errno was not restored";

  CheckMessage(cap, android::base::INFO, "67890");
}


TEST(logging, LOG_does_not_have_dangling_if) {
  CapturedStderr cap; // So the logging below has no side-effects.

  // Do the test two ways: once where we hypothesize that LOG()'s if
  // will evaluate to true (when severity is high enough) and once when we
  // expect it to evaluate to false (when severity is not high enough).
  bool flag = false;
  if (true)
    LOG(INFO) << "foobar";
  else
    flag = true;

  EXPECT_FALSE(flag) << "LOG macro probably has a dangling if with no else";

  flag = false;
  if (true)
    LOG(VERBOSE) << "foobar";
  else
    flag = true;

  EXPECT_FALSE(flag) << "LOG macro probably has a dangling if with no else";

  flag = false;
  if (true)
    LOG_S(::android::base::INFO) << "foobar";
  else
    flag = true;

  EXPECT_FALSE(flag) << "LOG_S macro probably has a dangling if with no else";

  flag = false;
  if (true)
    LOG_S(::android::base::VERBOSE) << "foobar";
  else
    flag = true;

  EXPECT_FALSE(flag) << "LOG_S macro probably has a dangling if with no else";
}

#define CHECK_PLOG_DISABLED(severity) \
  android::base::ScopedLogSeverity sls1(android::base::FATAL); \
  CapturedStderr cap1; \
  PLOG(severity) << "foo bar"; \
  ASSERT_EQ(0, lseek(cap1.fd(), 0, SEEK_CUR)); \

#define CHECK_PLOG_ENABLED(severity) \
  android::base::ScopedLogSeverity sls2(android::base::severity); \
  CapturedStderr cap2; \
  errno = ENOENT; \
  PLOG(severity) << "foobar"; \
  CheckMessage(cap2, android::base::severity, "foobar: No such file or directory"); \

TEST(logging, PLOG_FATAL) {
  ASSERT_DEATH({SuppressAbortUI(); PLOG(FATAL) << "foobar";}, "foobar");
}

TEST(logging, PLOG_FATAL_WITHOUT_ABORT_disabled) {
  CHECK_PLOG_DISABLED(FATAL_WITHOUT_ABORT);
}

TEST(logging, PLOG_FATAL_WITHOUT_ABORT_enabled) {
  CHECK_PLOG_ENABLED(FATAL_WITHOUT_ABORT);
}

TEST(logging, PLOG_ERROR_disabled) {
  CHECK_PLOG_DISABLED(ERROR);
}

TEST(logging, PLOG_ERROR_enabled) {
  CHECK_PLOG_ENABLED(ERROR);
}

TEST(logging, PLOG_WARNING_disabled) {
  CHECK_PLOG_DISABLED(WARNING);
}

TEST(logging, PLOG_WARNING_enabled) {
  CHECK_PLOG_ENABLED(WARNING);
}

TEST(logging, PLOG_INFO_disabled) {
  CHECK_PLOG_DISABLED(INFO);
}

TEST(logging, PLOG_INFO_enabled) {
  CHECK_PLOG_ENABLED(INFO);
}

TEST(logging, PLOG_DEBUG_disabled) {
  CHECK_PLOG_DISABLED(DEBUG);
}

TEST(logging, PLOG_DEBUG_enabled) {
  CHECK_PLOG_ENABLED(DEBUG);
}

TEST(logging, PLOG_VERBOSE_disabled) {
  CHECK_PLOG_DISABLED(VERBOSE);
}

TEST(logging, PLOG_VERBOSE_enabled) {
  CHECK_PLOG_ENABLED(VERBOSE);
}

#undef CHECK_PLOG_DISABLED
#undef CHECK_PLOG_ENABLED


#define CHECK_PLOG_S_DISABLED(severity) \
  android::base::ScopedLogSeverity sls1(android::base::FATAL); \
  CapturedStderr cap1; \
  PLOG_S(android::base::severity) << "foo bar"; \
  ASSERT_EQ(0, lseek(cap1.fd(), 0, SEEK_CUR)); \

#define CHECK_PLOG_S_ENABLED(severity) \
  android::base::ScopedLogSeverity sls2(android::base::severity); \
  CapturedStderr cap2; \
  errno = ENOENT; \
  PLOG_S(android::base::severity) << "foobar"; \
  CheckMessage(cap2, android::base::severity, "foobar: No such file or directory"); \

TEST(logging, PLOG_S_FATAL) {
  ASSERT_DEATH({SuppressAbortUI(); PLOG_S(::android::base::FATAL) << "foobar";}, "foobar");
}

TEST(logging, PLOG_S_FATAL_WITHOUT_ABORT_disabled) {
  CHECK_PLOG_S_DISABLED(FATAL_WITHOUT_ABORT);
}

TEST(logging, PLOG_S_FATAL_WITHOUT_ABORT_enabled) {
  CHECK_PLOG_S_ENABLED(FATAL_WITHOUT_ABORT);
}

TEST(logging, PLOG_S_ERROR_disabled) {
  CHECK_PLOG_S_DISABLED(ERROR);
}

TEST(logging, PLOG_S_ERROR_enabled) {
  CHECK_PLOG_S_ENABLED(ERROR);
}

TEST(logging, PLOG_S_WARNING_disabled) {
  CHECK_PLOG_S_DISABLED(WARNING);
}

TEST(logging, PLOG_S_WARNING_enabled) {
  CHECK_PLOG_S_ENABLED(WARNING);
}

TEST(logging, PLOG_S_INFO_disabled) {
  CHECK_PLOG_S_DISABLED(INFO);
}

TEST(logging, PLOG_S_INFO_enabled) {
  CHECK_PLOG_S_ENABLED(INFO);
}

TEST(logging, PLOG_S_DEBUG_disabled) {
  CHECK_PLOG_S_DISABLED(DEBUG);
}

TEST(logging, PLOG_S_DEBUG_enabled) {
  CHECK_PLOG_S_ENABLED(DEBUG);
}

TEST(logging, PLOG_S_VERBOSE_disabled) {
  CHECK_PLOG_S_DISABLED(VERBOSE);
}

TEST(logging, PLOG_S_VERBOSE_enabled) {
  CHECK_PLOG_S_ENABLED(VERBOSE);
}

#undef CHECK_PLOG_S_DISABLED
#undef CHECK_PLOG_S_ENABLED


TEST(logging, UNIMPLEMENTED) {
  std::string expected = android::base::StringPrintf("%s unimplemented ", __PRETTY_FUNCTION__);

  CapturedStderr cap;
  errno = ENOENT;
  UNIMPLEMENTED(ERROR);
  CheckMessage(cap, android::base::ERROR, expected.c_str());
}

static void NoopAborter(const char* msg ATTRIBUTE_UNUSED) {
  LOG(ERROR) << "called noop";
}

TEST(logging, LOG_FATAL_NOOP_ABORTER) {
  {
    android::base::SetAborter(NoopAborter);

    android::base::ScopedLogSeverity sls(android::base::ERROR);
    CapturedStderr cap;
    LOG(FATAL) << "foobar";
    CheckMessage(cap, android::base::FATAL, "foobar");
    CheckMessage(cap, android::base::ERROR, "called noop");

    android::base::SetAborter(android::base::DefaultAborter);
  }

  ASSERT_DEATH({SuppressAbortUI(); LOG(FATAL) << "foobar";}, "foobar");
}

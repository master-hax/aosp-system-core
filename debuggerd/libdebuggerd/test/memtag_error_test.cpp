/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <linux/prctl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <unistd.h>

#include <string>
#include "gtest/gtest.h"

#include <android-base/file.h>
#include <gtest/gtest.h>

#include <android/memtag-error.h>

#ifdef USE_SCUDO
constexpr bool kScudo = true;
#else
constexpr bool kScudo = false;
#endif

static inline bool running_with_mte() {
#ifdef __aarch64__
  int level = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
  return level >= 0 && (level & PR_TAGGED_ADDR_ENABLE) &&
         (level & PR_MTE_TCF_MASK) != PR_MTE_TCF_NONE;
#else
  return false;
#endif
}

template <typename F>
static void ExpectExitWithPTrace(pid_t tid, F f) {
  EXPECT_EXIT(
      {
        // This is complicated, but we need to make sure we definitely send
        // SIGCONT even if something crashes, otherwise the test just locks up.
        kill(tid, SIGSTOP);
        int pid = fork();
        if (pid == 0) {
          ptrace(PTRACE_SEIZE, tid, 0, 0);
          f();
          exit(testing::Test::HasFailure());
        } else {
          int wstatus;
          waitpid(pid, &wstatus, 0);
          kill(tid, SIGCONT);
          exit(WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : 1);
        }
      },
      testing::ExitedWithCode(0), "");
}

extern "C" void malloc_disable();
extern "C" void malloc_enable();

TEST(MemtagErrorTest, UseAfterFree) {
  if (!running_with_mte()) GTEST_SKIP() << "needs MTE";
  if (!kScudo) GTEST_SKIP() << "needs scudo";
  auto tid = gettid();
  volatile void* p = static_cast<volatile void*>(malloc(16));
  free(const_cast<void*>(p));
  malloc_disable();
  auto* x = AMemtagCrashInfo_get(reinterpret_cast<uintptr_t>(p));
  malloc_enable();
  ASSERT_NE(x, nullptr);
  malloc_disable();
  auto* e = AMemtagError_get(x);
  malloc_enable();
  ASSERT_NE(e, nullptr);
  auto* cause = AMemtagError_getCause(e, 0);
  ASSERT_NE(cause, nullptr);
  EXPECT_EQ(AMemtagCause_getType(cause), AMEMTAG_CAUSE_TYPE_USE_AFTER_FREE);
  EXPECT_EQ(AMemtagCause_getAllocationTid(cause), tid);
  EXPECT_EQ(AMemtagCause_getFreeTid(cause), tid);
}

TEST(MemtagErrorTest, UseAfterFreeForked) {
  if (!running_with_mte()) GTEST_SKIP() << "needs MTE";
  if (!kScudo) GTEST_SKIP() << "needs scudo";
  auto tid = gettid();
  volatile void* p = static_cast<volatile void*>(malloc(16));
  free(const_cast<void*>(p));
  malloc_disable();
  auto* x = AMemtagCrashInfo_get(reinterpret_cast<uintptr_t>(p));
  malloc_enable();
  EXPECT_NE(x, nullptr);
  ExpectExitWithPTrace(tid, [&] {
    auto* e = AMemtagError_get(x);
    EXPECT_NE(e, nullptr);
    auto* cause = AMemtagError_getCause(e, 0);
    EXPECT_NE(cause, nullptr);
    EXPECT_EQ(AMemtagCause_getType(cause), AMEMTAG_CAUSE_TYPE_USE_AFTER_FREE);
    EXPECT_EQ(AMemtagCause_getAllocationTid(cause), tid);
    EXPECT_EQ(AMemtagCause_getFreeTid(cause), tid);
  });
}

TEST(MemtagErrorTest, BufferOverflow) {
  if (!running_with_mte()) GTEST_SKIP() << "needs MTE";
  if (!kScudo) GTEST_SKIP() << "needs scudo";
  auto tid = gettid();
  volatile void* p = static_cast<volatile void*>(malloc(32));
  malloc_disable();
  auto* x = AMemtagCrashInfo_get(reinterpret_cast<uintptr_t>(p) + 32);
  EXPECT_NE(x, nullptr);
  auto* e = AMemtagError_get(x);
  EXPECT_NE(e, nullptr);
  auto* cause = AMemtagError_getCause(e, 0);
  EXPECT_NE(cause, nullptr);
  EXPECT_EQ(AMemtagCause_getType(cause), AMEMTAG_CAUSE_TYPE_OUT_OF_BOUNDS);
  EXPECT_EQ(AMemtagCause_getAllocationTid(cause), tid);
  malloc_enable();
  free(const_cast<void*>(p));
}

TEST(MemtagErrorTest, BufferOverflowForked) {
  if (!running_with_mte()) GTEST_SKIP() << "needs MTE";
  if (!kScudo) GTEST_SKIP() << "needs scudo";
  auto tid = gettid();
  volatile void* p = static_cast<volatile void*>(malloc(32));
  malloc_disable();
  auto* x = AMemtagCrashInfo_get(reinterpret_cast<uintptr_t>(p) + 32);
  malloc_enable();
  EXPECT_NE(x, nullptr);
  ExpectExitWithPTrace(tid, [&] {
    auto* e = AMemtagError_get(x);
    EXPECT_NE(e, nullptr);
    auto* cause = AMemtagError_getCause(e, 0);
    EXPECT_NE(cause, nullptr);
    EXPECT_EQ(AMemtagCause_getType(cause), AMEMTAG_CAUSE_TYPE_OUT_OF_BOUNDS);
    EXPECT_EQ(AMemtagCause_getAllocationTid(cause), tid);
  });
  free(const_cast<void*>(p));
}

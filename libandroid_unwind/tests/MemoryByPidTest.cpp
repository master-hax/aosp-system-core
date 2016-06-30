/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <vector>

#include <android-base/test_utils.h>
#include <android-base/file.h>
#include <gtest/gtest.h>

#include "Memory.h"

#include "LogFake.h"

class MemoryByPidTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ResetLogs();
  }

  static uint64_t NanoTime() {
    struct timespec t = { 0, 0 };
    clock_gettime(CLOCK_MONOTONIC, &t);
    return static_cast<uint64_t>(t.tv_sec * NS_PER_SEC + t.tv_nsec);
  }

  static bool Attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
      return false;
    }

    uint64_t start = NanoTime();
    siginfo_t si;
    while (TEMP_FAILURE_RETRY(ptrace(PTRACE_GETSIGINFO, pid, 0, &si)) < 0 && errno == ESRCH) {
      if ((NanoTime() - start) > 10 * NS_PER_SEC) {
        printf("%d: Failed to stop after 10 seconds.\n", pid);
        return false;
      }
      usleep(30);
    }
    return true;
  }

  static bool Detach(pid_t pid) {
    return ptrace(PTRACE_DETACH, pid, 0, 0) == 0;
  }

  static constexpr size_t NS_PER_SEC = 1000000000ULL;
};

TEST_F(MemoryByPidTest, remote_read) {
  std::vector<uint8_t> src(1024);
  memset(src.data(), 0x4c, 1024);

  pid_t pid;
  if ((pid = fork()) == 0) {
    while (true);
    exit(1);
  }
  ASSERT_LT(0, pid);

  ASSERT_TRUE(Attach(pid));

  MemoryByPid remote(pid);

  std::vector<uint8_t> dst(1024);
  ASSERT_TRUE(remote.Read(reinterpret_cast<uint64_t>(src.data()), dst.data(), 1024));
  ASSERT_EQ(0, memcmp(src.data(), dst.data(), 1024));
  for (size_t i = 0; i < 1024; i++) {
    ASSERT_EQ(0x4cU, dst[i]);
  }

  ASSERT_TRUE(Detach(pid));

  kill(pid, SIGKILL);
}

TEST_F(MemoryByPidTest, remote_read_fail) {
  uintptr_t pagesize = getpagesize();
  std::vector<uint8_t> src(pagesize * 3);
  memset(src.data(), 0x4c, pagesize * 3);

  uintptr_t aligned = (reinterpret_cast<uintptr_t>(src.data()) + pagesize - 1) & ~(pagesize - 1);
  ASSERT_EQ(0, mprotect((void*)(aligned + pagesize), pagesize, PROT_NONE));

  pid_t pid;
  if ((pid = fork()) == 0) {
    while (true);
    exit(1);
  }
  ASSERT_LT(0, pid);

  ASSERT_TRUE(Attach(pid));

  MemoryByPid remote(pid);

  std::vector<uint8_t> dst(pagesize);
  ASSERT_TRUE(remote.Read(static_cast<uint64_t>(aligned), dst.data(), pagesize));
  ASSERT_EQ(0, memcmp(src.data(), dst.data(), pagesize));
  for (size_t i = 0; i < 1024; i++) {
    ASSERT_EQ(0x4cU, dst[i]);
  }

  ASSERT_FALSE(remote.Read(static_cast<uint64_t>(aligned) + pagesize, dst.data(), 1));
  ASSERT_TRUE(remote.Read(static_cast<uint64_t>(aligned) + pagesize - 1, dst.data(), 1));
  ASSERT_FALSE(remote.Read(static_cast<uint64_t>(aligned) + pagesize - 4, dst.data(), 8));

  ASSERT_EQ(0, mprotect((void*)(aligned + pagesize), pagesize, PROT_READ | PROT_WRITE));

  ASSERT_TRUE(Detach(pid));

  kill(pid, SIGKILL);
}

TEST_F(MemoryByPidTest, remote_read_illegal) {
  pid_t pid;
  if ((pid = fork()) == 0) {
    while (true);
    exit(1);
  }
  ASSERT_LT(0, pid);

  ASSERT_TRUE(Attach(pid));

  MemoryByPid remote(pid);

  std::vector<uint8_t> dst(100);
  ASSERT_FALSE(remote.Read(0, dst.data(), 1));
  ASSERT_FALSE(remote.Read(0, dst.data(), 100));

  ASSERT_TRUE(Detach(pid));

  kill(pid, SIGKILL);
}

TEST_F(MemoryByPidTest, local_read) {
  std::vector<uint8_t> src(1024);
  memset(src.data(), 0x4c, 1024);

  MemoryByPid local(getpid());

  std::vector<uint8_t> dst(1024);
  ASSERT_TRUE(local.Read(reinterpret_cast<uintptr_t>(src.data()), dst.data(), 1024));
  ASSERT_EQ(0, memcmp(src.data(), dst.data(), 1024));
  for (size_t i = 0; i < 1024; i++) {
    ASSERT_EQ(0x4cU, dst[i]);
  }

  memset(src.data(), 0x23, 512);
  ASSERT_TRUE(local.Read(reinterpret_cast<uintptr_t>(src.data()), dst.data(), 1024));
  ASSERT_EQ(0, memcmp(src.data(), dst.data(), 1024));
  for (size_t i = 0; i < 512; i++) {
    ASSERT_EQ(0x23U, dst[i]);
  }
  for (size_t i = 512; i < 1024; i++) {
    ASSERT_EQ(0x4cU, dst[i]);
  }
}

TEST_F(MemoryByPidTest, local_read_illegal) {
  MemoryByPid local(getpid());

  std::vector<uint8_t> dst(100);
  ASSERT_FALSE(local.Read(0, dst.data(), 1));
  ASSERT_FALSE(local.Read(0, dst.data(), 100));
}

TEST_F(MemoryByPidTest, range_read) {
  std::vector<uint8_t> src(1024);
  memset(src.data(), 0x4c, 1024);

  uint64_t start = reinterpret_cast<uintptr_t>(src.data());
  MemoryByPidRange range(getpid(), start, start + src.size());

  std::vector<uint8_t> dst(1024);
  ASSERT_TRUE(range.Read(0, dst.data(), src.size()));
  ASSERT_EQ(0, memcmp(src.data(), dst.data(), 1024));
  for (size_t i = 0; i < 1024; i++) {
    ASSERT_EQ(0x4cU, dst[i]);
  }
}

TEST_F(MemoryByPidTest, range_read_near_limit) {
  std::vector<uint8_t> src(4096);
  memset(src.data(), 0x4c, 4096);

  uint64_t start = reinterpret_cast<uintptr_t>(src.data()) + 2048;
  MemoryByPidRange range(getpid(), start, start + 1024);

  std::vector<uint8_t> dst(1024);
  ASSERT_TRUE(range.Read(1020, dst.data(), 4));
  ASSERT_EQ(0, memcmp(&src[1020], dst.data(), 4));
  for (size_t i = 0; i < 4; i++) {
    ASSERT_EQ(0x4cU, dst[i]);
  }

  // Verify that reads outside of the range will fail.
  ASSERT_FALSE(range.Read(1020, dst.data(), 5));
  ASSERT_FALSE(range.Read(1024, dst.data(), 1));
  ASSERT_FALSE(range.Read(1024, dst.data(), 1024));
}

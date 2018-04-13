/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "android-base/process.h"

#include <paths.h>
#include <signal.h>

#include <gtest/gtest.h>

using namespace android::base;
using namespace std::string_literals;

TEST(process, ProcessBuilder_initializer) {
  // const char*
  ProcessBuilder bp1{"hello", "world"};
  // std::string
  ProcessBuilder bp2{"hello"s, "world"s};
}

TEST(process, Start_exit_0) {
  Process p = ProcessBuilder{_PATH_BSHELL, "-c", "true"}.Start();
  ASSERT_GT(p.GetPid(), 1);
  int status = p.WaitFor();
  ASSERT_NE(status, -1);

  // This is a fairly important property. Folks tend to test against 0 for success.
  ASSERT_EQ(status, 0);

  ASSERT_TRUE(WIFEXITED(status));
  ASSERT_FALSE(WIFSIGNALED(status));
  ASSERT_EQ(0, WEXITSTATUS(status));
}

TEST(process, RunAndWait_exit_0) {
  int status = ProcessBuilder{_PATH_BSHELL, "-c", "true"}.RunAndWait();
  ASSERT_NE(status, -1);
  ASSERT_TRUE(WIFEXITED(status));
  ASSERT_FALSE(WIFSIGNALED(status));
  ASSERT_EQ(0, WEXITSTATUS(status));
}

TEST(process, Start_exit_1) {
  Process p = ProcessBuilder{_PATH_BSHELL, "-c", "false"}.Start();
  ASSERT_GT(p.GetPid(), 1);
  int status = p.WaitFor();
  ASSERT_NE(status, -1);
  ASSERT_TRUE(WIFEXITED(status));
  ASSERT_FALSE(WIFSIGNALED(status));
  ASSERT_EQ(1, WEXITSTATUS(status));
}

TEST(process, RunAndWait_exit_1) {
  int status = ProcessBuilder{_PATH_BSHELL, "-c", "false"}.RunAndWait();
  ASSERT_NE(status, -1);
  ASSERT_TRUE(WIFEXITED(status));
  ASSERT_FALSE(WIFSIGNALED(status));
  ASSERT_EQ(1, WEXITSTATUS(status));
}

TEST(process, Start_SIGUSR1) {
  Process p = ProcessBuilder{_PATH_BSHELL, "-c", "kill -USR1 $$"}.Start();
  ASSERT_GT(p.GetPid(), 1);
  int status = p.WaitFor();
  ASSERT_NE(status, -1);
  ASSERT_FALSE(WIFEXITED(status));
  ASSERT_TRUE(WIFSIGNALED(status));
  ASSERT_EQ(SIGUSR1, WTERMSIG(status));
}

TEST(process, RunAndWait_SIGUSR1) {
  int status = ProcessBuilder{_PATH_BSHELL, "-c", "kill -USR1 $$"}.RunAndWait();
  ASSERT_FALSE(WIFEXITED(status));
  ASSERT_TRUE(WIFSIGNALED(status));
  ASSERT_EQ(SIGUSR1, WTERMSIG(status));
}

TEST(process, ExitStatusToString) {
  errno = EINVAL;
  EXPECT_EQ("failed to launch: Invalid argument", ExitStatusToString(-1));

  EXPECT_EQ("ran successfully", ExitStatusToString(W_EXITCODE(0, 0)));
  EXPECT_EQ("exited with status 1", ExitStatusToString(W_EXITCODE(1, 0)));
  EXPECT_EQ("was killed by signal 3 (Quit)", ExitStatusToString(0x80 | SIGQUIT));
  EXPECT_EQ("was stopped by signal 3 (Quit)", ExitStatusToString(W_STOPCODE(SIGQUIT)));
}

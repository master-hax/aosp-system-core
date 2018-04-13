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
  ASSERT_TRUE(p.WaitFor());
  ASSERT_TRUE(p.GetExitStatus().DidExit());
  ASSERT_FALSE(p.GetExitStatus().WasSignaled());
  ASSERT_EQ(0, p.GetExitStatus().ExitValue());
}

TEST(process, RunAndWait_exit_0) {
  ExitStatus s = ProcessBuilder{_PATH_BSHELL, "-c", "true"}.RunAndWait();
  ASSERT_TRUE(s.DidExit());
  ASSERT_FALSE(s.WasSignaled());
  ASSERT_EQ(0, s.ExitValue());
}

TEST(process, Start_exit_1) {
  Process p = ProcessBuilder{_PATH_BSHELL, "-c", "false"}.Start();
  ASSERT_GT(p.GetPid(), 1);
  ASSERT_TRUE(p.WaitFor());
  ASSERT_TRUE(p.GetExitStatus().DidExit());
  ASSERT_FALSE(p.GetExitStatus().WasSignaled());
  ASSERT_EQ(1, p.GetExitStatus().ExitValue());
}

TEST(process, RunAndWait_exit_1) {
  ExitStatus s = ProcessBuilder{_PATH_BSHELL, "-c", "false"}.RunAndWait();
  ASSERT_TRUE(s.DidExit());
  ASSERT_FALSE(s.WasSignaled());
  ASSERT_EQ(1, s.ExitValue());
}

TEST(process, Start_SIGUSR1) {
  Process p = ProcessBuilder{_PATH_BSHELL, "-c", "kill -USR1 $$"}.Start();
  ASSERT_GT(p.GetPid(), 1);
  ASSERT_TRUE(p.WaitFor());
  ASSERT_FALSE(p.GetExitStatus().DidExit());
  ASSERT_TRUE(p.GetExitStatus().WasSignaled());
  ASSERT_EQ(SIGUSR1, p.GetExitStatus().Signal());
}

TEST(process, RunAndWait_SIGUSR1) {
  ExitStatus s = ProcessBuilder{_PATH_BSHELL, "-c", "kill -USR1 $$"}.RunAndWait();
  ASSERT_FALSE(s.DidExit());
  ASSERT_TRUE(s.WasSignaled());
  ASSERT_EQ(SIGUSR1, s.Signal());
}

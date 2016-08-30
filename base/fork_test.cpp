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

#include <stdlib.h>
#include <unistd.h>

#include <android-base/fork.h>
#include <gtest/gtest.h>

using android::base::fork_helper;

TEST(fork, child_exit_success) {
  fork_helper<> f{[]() { return 0; }};
  ASSERT_TRUE(f);
  ASSERT_TRUE(f.pid() > 0);
  ASSERT_TRUE(f.wait());
}

TEST(fork, child_exit_failure) {
  fork_helper<> f{[]() { return 1; }};
  ASSERT_TRUE(f);
  ASSERT_TRUE(f.pid() > 0);
  ASSERT_FALSE(f.wait());
}

TEST(fork, child_crash) {
  fork_helper<> f{[]() {
    abort();
    return 0;
  }};
  ASSERT_TRUE(f);
  ASSERT_TRUE(f.pid() > 0);
  ASSERT_FALSE(f.wait());
}

TEST(fork, child_kill) {
  fork_helper<> f{[]() {
    while (1) sleep(1);
    return 0;
  }};
  ASSERT_TRUE(f);
  ASSERT_TRUE(f.pid() > 0);
  ASSERT_TRUE(f.kill());
  ASSERT_FALSE(f.wait());
}

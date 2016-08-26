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

#include <android-base/multiprocess.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sstream>
#include <string>

#include <gtest/gtest.h>

TEST(fork_helper, child_exit_success) {
  android::base::fork_helper f;
  ASSERT_TRUE(f);

  if (!f.is_parent()) _exit(0);
  ASSERT_TRUE(f.wait_for_child());
}

TEST(fork_helper, child_exit_failure) {
  android::base::fork_helper f;
  ASSERT_TRUE(f);

  if (!f.is_parent()) _exit(1);
  ASSERT_FALSE(f.wait_for_child());
}

TEST(fork_helper, child_crash) {
  android::base::fork_helper f;
  ASSERT_TRUE(f);

  if (!f.is_parent()) abort();
  ASSERT_FALSE(f.wait_for_child());
}

TEST(fork_helper, child_kill) {
  android::base::fork_helper f;
  ASSERT_TRUE(f);

  if (!f.is_parent())
    while (1) sleep(1);
  ASSERT_TRUE(f.kill_child(SIGTERM));
  ASSERT_FALSE(f.wait_for_child());
}

class MultiprocessTest : public testing::Test {
 protected:
  MultiprocessTest() : testing::Test{}, sp{}, fork{} {}

  virtual void SetUp() {
    ASSERT_TRUE(sp);
    ASSERT_TRUE(fork);
  }

  virtual void TearDown() {
    if (fork.is_parent())
      ASSERT_TRUE(fork.wait_for_child());
    else
      _exit(0);
  }

 protected:
  android::base::unique_socketpair sp;
  android::base::fork_helper fork;
};

class unique_socketpair : public MultiprocessTest {};

TEST_F(unique_socketpair, unique_socketpair) {
  if (fork.is_parent()) {
    android::base::unique_fd fd{sp.release(0)};
    int buf = 0;
    auto ret = TEMP_FAILURE_RETRY(write(fd, &buf, sizeof(buf)));
    ASSERT_EQ(static_cast<ssize_t>(sizeof(buf)), ret);
  } else {
    android::base::unique_fd fd{sp.release(1)};
    int buf;
    auto ret = TEMP_FAILURE_RETRY(read(fd, &buf, sizeof(buf)));
    if (ret != static_cast<ssize_t>(sizeof(buf))) _exit(1);
  }
}

constexpr int ITERS = 10000;
constexpr unsigned int ITERS_U = ITERS;
class local_socketstream : public MultiprocessTest {};

TEST_F(local_socketstream, pingpong_int) {
  android::base::local_socketstream ss{sp, fork};

  if (fork.is_parent()) {
    for (int i = 0; i < ITERS; i++) {
      int val;
      ASSERT_TRUE(ss << i) << "sending " << i << " failed: " << strerror(errno);
      ASSERT_TRUE(ss >> val) << "receiving " << i
                             << "failed: " << strerror(errno);
      ASSERT_EQ(i, val) << "integer value didn't survive round trip";
    }

    for (unsigned int i = 0; i < ITERS_U; i++) {
      unsigned int val;
      ASSERT_TRUE(ss << i) << "sending " << i << " failed: " << strerror(errno);
      ASSERT_TRUE(ss >> val) << "receiving " << i
                             << "failed: " << strerror(errno);
      ASSERT_EQ(i, val) << "unsigned integer value didn't survive round trip";
    }
  } else {
    for (int i = 0; i < ITERS; i++) {
      int val;
      if (!(ss >> val)) {
        std::cerr << strerror(errno) << std::endl;
        _exit(1);
      }
      if (!(ss << val)) {
        std::cerr << strerror(errno) << std::endl;
        _exit(1);
      }
    }

    for (unsigned int i = 0; i < ITERS_U; i++) {
      unsigned int val;
      if (!(ss >> val)) _exit(1);
      if (!(ss << val)) _exit(1);
    }
  }
}

// This test requires procfs
#if defined(__linux__)
TEST_F(local_socketstream, pingpong_fd) {
  android::base::local_socketstream ss{sp, fork};

  if (fork.is_parent()) {
    for (int i = 0; i < ITERS; i++) {
      android::base::unique_fd devnull{open("/dev/null", O_RDONLY)};
      ASSERT_NE(-1, devnull) << "opening /dev/null failed: " << strerror(errno);
      ASSERT_TRUE(ss << devnull) << "sending fd failed: " << strerror(errno);

      android::base::unique_fd devnull2;
      ASSERT_TRUE(ss >> devnull2) << "receiving fd failed: " << strerror(errno);

      ASSERT_GE(devnull2, 0) << "received invalid fd";
      ASSERT_NE(devnull, devnull2) << "fd wasn't duplicated during round trip";

      std::stringstream ss;
      ss << "/proc/self/fd/" << devnull2.get();
      auto fdPath = ss.str();

      char path[PATH_MAX]{};
      auto err = readlink(fdPath.c_str(), path, sizeof(path));
      ASSERT_NE(-1, err) << "readlink() failed: " << strerror(errno);
      ASSERT_STREQ("/dev/null", path) << "fd target didn't survive round trip";
    }
  } else {
    for (int i = 0; i < ITERS; i++) {
      android::base::unique_fd val;
      if (!(ss >> val)) _exit(1);
      if (!(ss << val)) _exit(1);
    }
  }
}
#endif

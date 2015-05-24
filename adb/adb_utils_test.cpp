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

#include "adb_utils.h"

#ifdef _WIN32
#include <windows.h>
#include <userenv.h>
#endif

#include <string>

#include <gtest/gtest.h>

#include "base/macros.h"

#ifdef _WIN32
static std::string subdir(const char* parent, const char* child) {
  std::string str(parent);
  str += OS_PATH_SEPARATOR;
  str += child;
  return str;
}
#endif

TEST(adb_utils, directory_exists) {
#ifdef _WIN32
  char profiles_dir[MAX_PATH];
  DWORD cch = arraysize(profiles_dir);

  // On typical Windows 7, returns C:\Users
  ASSERT_TRUE(GetProfilesDirectory(profiles_dir, &cch));

  ASSERT_TRUE(directory_exists(profiles_dir));

  // On modern (English?) Windows, this is a directory symbolic link to
  // C:\ProgramData. Symbolic links are rare on Windows and the user requires
  // a special permission (by default granted to Administrative users) to
  // create symbolic links.
  ASSERT_FALSE(directory_exists(subdir(profiles_dir, "All Users")));

  // On modern (English?) Windows, this is a directory junction to
  // C:\Users\Default. Junctions are used throughout user profile directories
  // for backwards compatibility and they don't require any special permissions
  // to create.
  ASSERT_FALSE(directory_exists(subdir(profiles_dir, "Default User")));

  ASSERT_FALSE(directory_exists(subdir(profiles_dir, "does-not-exist")));
#else
  ASSERT_TRUE(directory_exists("/proc"));
  ASSERT_FALSE(directory_exists("/proc/self")); // Symbolic link.
  ASSERT_FALSE(directory_exists("/proc/does-not-exist"));
#endif
}

TEST(adb_utils, escape_arg) {
  ASSERT_EQ(R"('')", escape_arg(""));

  ASSERT_EQ(R"('abc')", escape_arg("abc"));

  ASSERT_EQ(R"(' abc')", escape_arg(" abc"));
  ASSERT_EQ(R"(''\''abc')", escape_arg("'abc"));
  ASSERT_EQ(R"('"abc')", escape_arg("\"abc"));
  ASSERT_EQ(R"('\abc')", escape_arg("\\abc"));
  ASSERT_EQ(R"('(abc')", escape_arg("(abc"));
  ASSERT_EQ(R"(')abc')", escape_arg(")abc"));

  ASSERT_EQ(R"('abc abc')", escape_arg("abc abc"));
  ASSERT_EQ(R"('abc'\''abc')", escape_arg("abc'abc"));
  ASSERT_EQ(R"('abc"abc')", escape_arg("abc\"abc"));
  ASSERT_EQ(R"('abc\abc')", escape_arg("abc\\abc"));
  ASSERT_EQ(R"('abc(abc')", escape_arg("abc(abc"));
  ASSERT_EQ(R"('abc)abc')", escape_arg("abc)abc"));

  ASSERT_EQ(R"('abc ')", escape_arg("abc "));
  ASSERT_EQ(R"('abc'\''')", escape_arg("abc'"));
  ASSERT_EQ(R"('abc"')", escape_arg("abc\""));
  ASSERT_EQ(R"('abc\')", escape_arg("abc\\"));
  ASSERT_EQ(R"('abc(')", escape_arg("abc("));
  ASSERT_EQ(R"('abc)')", escape_arg("abc)"));
}

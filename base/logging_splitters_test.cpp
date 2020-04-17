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

#include "logging_splitters.h"

#include <string>
#include <vector>

#include <android-base/strings.h>
#include <gtest/gtest.h>

namespace android {
namespace base {

void TestSplitter(bool logd, const std::string& tag, const std::string& input,
                  const std::vector<std::string>& expected_output) {
  std::vector<std::string> output;
  auto logger_function = [&](LogId, LogSeverity, const char*, const char*, unsigned int,
                             const char* msg, int length) {
    if (length == -1) {
      output.push_back(msg);
    } else {
      output.push_back(std::string(msg, length));
    }
  };
  if (logd) {
    SplitByLogdLines(MAIN, ERROR, tag.c_str(), "file.cpp", 1000, input.c_str(), logger_function,
                     nullptr);

  } else {
    SplitByLines(MAIN, ERROR, tag.c_str(), "file.cpp", 1000, input.c_str(), logger_function,
                 nullptr);
  }

  EXPECT_EQ(expected_output, output);
}

void TestNewlineSplitter(const std::string& tag, const std::string& input,
                         const std::vector<std::string>& expected_output) {
  TestSplitter(false, tag, input, expected_output);
}

void TestLogdNewlineSplitter(const std::string& tag, const std::string& input,
                             const std::vector<std::string>& expected_output) {
  TestSplitter(true, tag, input, expected_output);
}

TEST(logging_splitters, NewlineSplitter_EmptyString) {
  TestNewlineSplitter("tag", "", std::vector<std::string>{""});
}

TEST(logging_splitters, NewlineSplitter_BasicString) {
  TestNewlineSplitter("tag", "normal string", std::vector<std::string>{"normal string"});
}

TEST(logging_splitters, NewlineSplitter_ormalBasicStringTrailingNewline) {
  TestNewlineSplitter("tag", "normal string\n", std::vector<std::string>{"normal string", ""});
}

TEST(logging_splitters, NewlineSplitter_MultilineTrailing) {
  TestNewlineSplitter("tag", "normal string\nsecond string\nthirdstring",
                      std::vector<std::string>{"normal string", "second string", "thirdstring"});
}

TEST(logging_splitters, NewlineSplitter_MultilineTrailingNewline) {
  TestNewlineSplitter(
      "tag", "normal string\nsecond string\nthirdstring\n",
      std::vector<std::string>{"normal string", "second string", "thirdstring", ""});
}

TEST(logging_splitters, NewlineSplitter_MultilineEmbeddedNewlines) {
  TestNewlineSplitter(
      "tag", "normal string\n\n\nsecond string\n\nthirdstring\n",
      std::vector<std::string>{"normal string", "", "", "second string", "", "thirdstring", ""});
}

TEST(logging_splitters, LogdNewlineSplitter_EmptyString) {
  TestLogdNewlineSplitter("tag", "", std::vector<std::string>{""});
}

TEST(logging_splitters, LogdNewlineSplitter_BasicString) {
  TestLogdNewlineSplitter("tag", "normal string", std::vector<std::string>{"normal string"});
}

TEST(logging_splitters, LogdNewlineSplitter_NormalBasicStringTrailingNewline) {
  TestLogdNewlineSplitter("tag", "normal string\n", std::vector<std::string>{"normal string\n"});
}

TEST(logging_splitters, LogdNewlineSplitter_MultilineTrailing) {
  TestLogdNewlineSplitter("tag", "normal string\nsecond string\nthirdstring",
                          std::vector<std::string>{"normal string\nsecond string\nthirdstring"});
}

TEST(logging_splitters, LogdNewlineSplitter_MultilineTrailingNewline) {
  TestLogdNewlineSplitter("tag", "normal string\nsecond string\nthirdstring\n",
                          std::vector<std::string>{"normal string\nsecond string\nthirdstring\n"});
}

TEST(logging_splitters, LogdNewlineSplitter_MultilineEmbeddedNewlines) {
  TestLogdNewlineSplitter(
      "tag", "normal string\n\n\nsecond string\n\nthirdstring\n",
      std::vector<std::string>{"normal string\n\n\nsecond string\n\nthirdstring\n"});
}

// This test should return the same string, the logd logger itself will truncate down to size.
// This has historically been the behavior both in libbase and liblog.
TEST(logging_splitters, LogdNewlineSplitter_HugeLineNoNewline) {
  auto long_string = std::string(LOGGER_ENTRY_MAX_PAYLOAD, 'x');
  ASSERT_EQ(LOGGER_ENTRY_MAX_PAYLOAD, static_cast<int>(long_string.size()));

  TestLogdNewlineSplitter("tag", long_string, std::vector{long_string});
}

TEST(logging_splitters, LogdNewlineSplitter_MultipleHugeLineNoNewline) {
  auto long_string_x = std::string(LOGGER_ENTRY_MAX_PAYLOAD, 'x');
  auto long_string_y = std::string(LOGGER_ENTRY_MAX_PAYLOAD, 'y');
  auto long_string_z = std::string(LOGGER_ENTRY_MAX_PAYLOAD, 'z');

  auto long_strings = long_string_x + '\n' + long_string_y + '\n' + long_string_z;

  TestLogdNewlineSplitter("tag", long_strings,
                          std::vector{long_string_x, long_string_y, long_string_z});
}

// With a ~4k buffer, we should print 2 long strings per logger call.
TEST(logging_splitters, LogdNewlineSplitter_Multiple2kLines) {
  std::vector expected = {
      std::string(2000, 'a') + '\n' + std::string(2000, 'b'),
      std::string(2000, 'c') + '\n' + std::string(2000, 'd'),
      std::string(2000, 'e') + '\n' + std::string(2000, 'f'),
  };

  auto long_strings = Join(expected, '\n');

  TestLogdNewlineSplitter("tag", long_strings, expected);
}

TEST(logging_splitters, LogdNewlineSplitter_ExactSizedLines) {
  const char* tag = "tag";
  ptrdiff_t max_size = LOGGER_ENTRY_MAX_PAYLOAD - strlen(tag) - 35;
  auto long_string_a = std::string(max_size, 'a');
  auto long_string_b = std::string(max_size, 'b');
  auto long_string_c = std::string(max_size, 'c');

  auto long_strings = long_string_a + '\n' + long_string_b + '\n' + long_string_c;

  TestLogdNewlineSplitter(tag, long_strings,
                          std::vector{long_string_a, long_string_b, long_string_c});
}

TEST(logging_splitters, LogdNewlineSplitter_UnderEqualOver) {
  const char* tag = "tag";
  ptrdiff_t max_size = LOGGER_ENTRY_MAX_PAYLOAD - strlen(tag) - 35;

  auto first_string_size = 1000;
  auto first_string = std::string(first_string_size, 'a');
  auto second_string_size = max_size - first_string_size - 1;
  auto second_string = std::string(second_string_size, 'b');

  auto exact_string = std::string(max_size, 'c');

  auto large_string = std::string(max_size + 50, 'd');

  auto final_string = std::string("final string!\n\nfinal \n \n final \n");

  std::vector expected = {first_string + '\n' + second_string, exact_string, large_string,
                          final_string};

  auto long_strings = Join(expected, '\n');

  TestLogdNewlineSplitter(tag, long_strings, expected);
}

}  // namespace base
}  // namespace android

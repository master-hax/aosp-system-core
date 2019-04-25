/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <gtest/gtest.h>

size_t convertPrintable(char* p, const char* message, size_t messageLen);

TEST(liblog, convertPrintable_ascii) {
  auto input = "easy string, output same";
  auto output_size = convertPrintable(nullptr, input, strlen(input));
  EXPECT_EQ(output_size, strlen(input));

  char output[output_size];

  output_size = convertPrintable(output, input, strlen(input));
  EXPECT_EQ(output_size, strlen(input));
  EXPECT_STREQ(input, output);
}

TEST(liblog, convertPrintable_escapes) {
  // Note that \t is not escaped.
  auto input = "escape\a\b\t\v\f\r\\";
  auto expected_output = "escape\\a\\b\t\\v\\f\\r\\\\";
  auto output_size = convertPrintable(nullptr, input, strlen(input));
  EXPECT_EQ(output_size, strlen(expected_output));

  char output[output_size];

  output_size = convertPrintable(output, input, strlen(input));
  EXPECT_EQ(output_size, strlen(expected_output));
  EXPECT_STREQ(expected_output, output);
}

TEST(liblog, convertPrintable_validutf8) {
  auto input = u8"¢ह€𐍈";
  auto output_size = convertPrintable(nullptr, input, strlen(input));
  EXPECT_EQ(output_size, strlen(input));

  char output[output_size];

  output_size = convertPrintable(output, input, strlen(input));
  EXPECT_EQ(output_size, strlen(input));
  EXPECT_STREQ(input, output);
}

TEST(liblog, convertPrintable_invalidutf8) {
  auto input = "\200\302\001\340\244\006\340\006\360\220\215\006\360\220\006\360\016";
  auto expected_output =
      "\\200\\302\\001\\340\\244\\006\\340\\006\\360\\220\\215\\006\\360\\220\\006\\360\\016";
  auto output_size = convertPrintable(nullptr, input, strlen(input));

  char output[output_size];

  output_size = convertPrintable(output, input, strlen(input));
  EXPECT_EQ(output_size, strlen(expected_output));
  EXPECT_STREQ(expected_output, output);
}

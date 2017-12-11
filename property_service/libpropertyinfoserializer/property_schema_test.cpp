/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "property_info_serializer/property_schema.h"

#include <gtest/gtest.h>

namespace android {
namespace properties {

TEST(property_schema, CheckSchema_string) {
  EXPECT_TRUE(CheckSchema("string", ""));
  EXPECT_TRUE(CheckSchema("string", "-234"));
  EXPECT_TRUE(CheckSchema("string", "234"));
  EXPECT_TRUE(CheckSchema("string", "true"));
  EXPECT_TRUE(CheckSchema("string", "false"));
  EXPECT_TRUE(CheckSchema("string", "45645634563456345634563456"));
  EXPECT_TRUE(CheckSchema("string", "some other string"));
}

TEST(property_schema, CheckSchema_int) {
  EXPECT_FALSE(CheckSchema("int", ""));
  EXPECT_FALSE(CheckSchema("int", "abc"));
  EXPECT_FALSE(CheckSchema("int", "-abc"));
  EXPECT_TRUE(CheckSchema("int", "0"));
  EXPECT_TRUE(CheckSchema("int", std::to_string(std::numeric_limits<int64_t>::min())));
  EXPECT_TRUE(CheckSchema("int", std::to_string(std::numeric_limits<int64_t>::max())));
  EXPECT_TRUE(CheckSchema("int", "123"));
  EXPECT_TRUE(CheckSchema("int", "-123"));

  EXPECT_FALSE(CheckSchema("int -10 10", ""));
  EXPECT_FALSE(CheckSchema("int -10 10", "abc"));
  EXPECT_FALSE(CheckSchema("int -10 10", "-abc"));
  EXPECT_FALSE(CheckSchema("int -10 10", std::to_string(std::numeric_limits<int64_t>::min())));
  EXPECT_FALSE(CheckSchema("int -10 10", std::to_string(std::numeric_limits<int64_t>::max())));
  EXPECT_FALSE(CheckSchema("int -10 10", "-11"));
  EXPECT_FALSE(CheckSchema("int -10 10", "11"));
  EXPECT_TRUE(CheckSchema("int -10 10", "-10"));
  EXPECT_TRUE(CheckSchema("int -10 10", "-1"));
  EXPECT_TRUE(CheckSchema("int -10 10", "0"));
  EXPECT_TRUE(CheckSchema("int -10 10", "1"));
  EXPECT_TRUE(CheckSchema("int -10 10", "10"));

  EXPECT_FALSE(CheckSchema("int -500 -500", "-499"));
  EXPECT_TRUE(CheckSchema("int -500 -500", "-500"));
  EXPECT_FALSE(CheckSchema("int -500 -500", "-501"));
  EXPECT_FALSE(CheckSchema("int -500 -500", "500"));
}

TEST(property_schema, CheckSchema_uint) {
  EXPECT_FALSE(CheckSchema("uint", ""));
  EXPECT_FALSE(CheckSchema("uint", "abc"));
  EXPECT_FALSE(CheckSchema("uint", "-abc"));
  EXPECT_TRUE(CheckSchema("uint", "0"));
  EXPECT_TRUE(CheckSchema("uint", std::to_string(std::numeric_limits<uint64_t>::max())));
  EXPECT_TRUE(CheckSchema("uint", "123"));
  EXPECT_FALSE(CheckSchema("uint", "-123"));

  EXPECT_FALSE(CheckSchema("uint 0 1", ""));
  EXPECT_FALSE(CheckSchema("uint 0 1", "abc"));
  EXPECT_FALSE(CheckSchema("uint 0 1", "-abc"));
  EXPECT_FALSE(CheckSchema("uint 0 1", std::to_string(std::numeric_limits<uint64_t>::max())));
  EXPECT_FALSE(CheckSchema("uint 0 1", "-1"));
  EXPECT_FALSE(CheckSchema("uint 0 1", "2"));
  EXPECT_TRUE(CheckSchema("uint 0 1", "0"));
  EXPECT_TRUE(CheckSchema("uint 0 1", "1"));

  EXPECT_FALSE(CheckSchema("uint 500 500", "-500"));
  EXPECT_FALSE(CheckSchema("uint 500 500", "499"));
  EXPECT_TRUE(CheckSchema("uint 500 500", "500"));
  EXPECT_FALSE(CheckSchema("uint 500 500", "501"));
}

TEST(property_schema, CheckSchema_enum) {
  EXPECT_FALSE(CheckSchema("enum abc", ""));
  EXPECT_FALSE(CheckSchema("enum abc", "ab"));
  EXPECT_FALSE(CheckSchema("enum abc", "abcd"));
  EXPECT_FALSE(CheckSchema("enum 123 456 789", "0"));

  EXPECT_TRUE(CheckSchema("enum abc", "abc"));
  EXPECT_TRUE(CheckSchema("enum 123 456 789", "123"));
  EXPECT_TRUE(CheckSchema("enum 123 456 789", "456"));
  EXPECT_TRUE(CheckSchema("enum 123 456 789", "789"));
}

TEST(property_schema, IsSchemaValid) {
  EXPECT_FALSE(IsSchemaValid("not"));
  EXPECT_FALSE(IsSchemaValid("valid"));

  EXPECT_TRUE(IsSchemaValid("string"));
  EXPECT_TRUE(IsSchemaValid("bool"));
  EXPECT_FALSE(IsSchemaValid("string other"));
  EXPECT_FALSE(IsSchemaValid("bool other"));

  EXPECT_TRUE(IsSchemaValid("int"));
  EXPECT_TRUE(IsSchemaValid("int -10 10"));
  EXPECT_TRUE(IsSchemaValid("int 0 10"));
  EXPECT_TRUE(IsSchemaValid("int 10 10"));
  EXPECT_TRUE(IsSchemaValid("int 0 " + std::to_string(std::numeric_limits<int64_t>::max())));
  EXPECT_TRUE(IsSchemaValid("int " + std::to_string(std::numeric_limits<int64_t>::min()) + " 0"));
  EXPECT_FALSE(IsSchemaValid("int 10"));
  EXPECT_FALSE(IsSchemaValid("int 10 9"));
  EXPECT_FALSE(IsSchemaValid("int 10 -11"));
  EXPECT_FALSE(IsSchemaValid("int 0 " + std::to_string(std::numeric_limits<int64_t>::min())));
  EXPECT_FALSE(IsSchemaValid("int " + std::to_string(std::numeric_limits<int64_t>::max()) + " 0"));
  EXPECT_FALSE(IsSchemaValid("int 0 1" + std::to_string(std::numeric_limits<int64_t>::max())));
  EXPECT_FALSE(IsSchemaValid("int " + std::to_string(std::numeric_limits<int64_t>::min()) + "9 0"));

  EXPECT_TRUE(IsSchemaValid("uint"));
  EXPECT_FALSE(IsSchemaValid("uint -10 10"));
  EXPECT_TRUE(IsSchemaValid("uint 0 10"));
  EXPECT_TRUE(IsSchemaValid("uint 10 10"));
  EXPECT_TRUE(IsSchemaValid("uint 0 " + std::to_string(std::numeric_limits<uint64_t>::max())));
  EXPECT_FALSE(IsSchemaValid("uint 10"));
  EXPECT_FALSE(IsSchemaValid("uint 10 9"));
  EXPECT_FALSE(IsSchemaValid("uint 10 -11"));
  EXPECT_FALSE(IsSchemaValid("uint " + std::to_string(std::numeric_limits<int64_t>::max()) + " 0"));
  EXPECT_FALSE(IsSchemaValid("uint 0 1" + std::to_string(std::numeric_limits<int64_t>::max())));

  EXPECT_FALSE(IsSchemaValid("enum"));
  EXPECT_TRUE(IsSchemaValid("enum other"));
  EXPECT_TRUE(IsSchemaValid("enum other and another"));
}

}  // namespace properties
}  // namespace android

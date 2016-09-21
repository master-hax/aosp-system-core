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

#include "android-base/properties.h"

#include <gtest/gtest.h>

#include <string>

TEST(properties, smoke) {
  android::base::SetProperty("debug.libbase.property_test", "hello");

  std::string s;
  android::base::GetProperty("debug.libbase.property_test", &s);
  ASSERT_EQ("hello", s);

  android::base::SetProperty("debug.libbase.property_test", "world");
  android::base::GetProperty("debug.libbase.property_test", &s);
  ASSERT_EQ("world", s);

  s = "";
  android::base::GetProperty("this.property.does.not.exist", &s);
  ASSERT_EQ("", s);

  s = "default";
  android::base::GetProperty("this.property.does.not.exist", &s);
  ASSERT_EQ("default", s);
}

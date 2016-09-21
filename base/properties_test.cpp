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

  std::string s = android::base::GetProperty("debug.libbase.property_test", "");
  ASSERT_EQ("hello", s);

  android::base::SetProperty("debug.libbase.property_test", "world");
  s = android::base::GetProperty("debug.libbase.property_test", "");
  ASSERT_EQ("world", s);

  s = android::base::GetProperty("this.property.does.not.exist", "");
  ASSERT_EQ("", s);

  s = android::base::GetProperty("this.property.does.not.exist", "default");
  ASSERT_EQ("default", s);
}

TEST(properties, empty) {
  // Because you can't delete a property, people "delete" them by
  // setting them to the empty string. In that case we'd want to
  // keep the default value (like cutils' property_get did).
  android::base::SetProperty("debug.libbase.property_test", "");
  std::string s = android::base::GetProperty("debug.libbase.property_test", "default");
  ASSERT_EQ("default", s);
}

static void CheckGetBoolProperty(bool expected, const std::string& value, bool default_value) {
  android::base::SetProperty("debug.libbase.property_test", value.c_str());
  ASSERT_EQ(expected, android::base::GetBoolProperty("debug.libbase.property_test", default_value));
}

TEST(properties, GetBoolProperty_true) {
  CheckGetBoolProperty(true, "1", false);
  CheckGetBoolProperty(true, "y", false);
  CheckGetBoolProperty(true, "yes", false);
  CheckGetBoolProperty(true, "on", false);
  CheckGetBoolProperty(true, "true", false);
}

TEST(properties, GetBoolProperty_false) {
  CheckGetBoolProperty(false, "0", true);
  CheckGetBoolProperty(false, "n", true);
  CheckGetBoolProperty(false, "no", true);
  CheckGetBoolProperty(false, "off", true);
  CheckGetBoolProperty(false, "false", true);
}

TEST(properties, GetBoolProperty_default) {
  CheckGetBoolProperty(true, "burp", true);
  CheckGetBoolProperty(false, "burp", false);
}

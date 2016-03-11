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

#include "uptime_parser.h"

#include <string>
#include <android-base/file.h>
#include <gtest/gtest.h>

time_t ReadUptime() {
  std::string uptime_str;
  if (!android::base::ReadFileToString("/proc/uptime", &uptime_str)) {
    return -1;
  }

  // Cast to int to round down.
  return static_cast<time_t>(strtod(uptime_str.c_str(), NULL));
}

TEST(UptimeParser, ParseUptime) {
  time_t uptime = ReadUptime();
  EXPECT_EQ(uptime, bootstat::ParseUptime());
}

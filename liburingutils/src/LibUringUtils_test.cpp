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

#include <liburingutils/LibUringUtils.h>

#include <gtest/gtest.h>

class LibUringUtilsTest : public testing::Test {
public:
    void testIsIouringEnabled(bool expectedResult) {
        EXPECT_EQ(LibUringUtils::isIouringEnabled(), expectedResult);
    }
};

TEST_F(LibUringUtilsTest, ReturnsIouringNotEnabled) {
    // TODO: b/385143770 - Change this behavior to check the OS version and Liburing version.
    testIsIouringEnabled(false);
}

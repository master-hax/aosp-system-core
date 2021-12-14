/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "utils/ErrorsMacros.h"

#include <android-base/result.h>

#include <gtest/gtest.h>

using namespace android;

using android::base::Result;

status_t success_or_fail(bool success) {
    if (success)
        return OK;
    else
        return PERMISSION_DENIED;
}

TEST(errors, unwrap_or_return) {
    auto f = [](bool success, int* val) -> status_t {
        OR_RETURN(success_or_fail(success));
        *val = 10;
        return OK;
    };

    int val;
    status_t s = f(true, &val);
    EXPECT_EQ(OK, s);
    EXPECT_EQ(10, val);

    val = 0;  // reset
    status_t q = f(false, &val);
    EXPECT_EQ(PERMISSION_DENIED, q);
    EXPECT_EQ(0, val);
}

TEST(errors, unwrap_or_return_result) {
    auto f = [](bool success) -> Result<std::string, status_t> {
        OR_RETURN(success_or_fail(success));
        return "apple";
    };

    auto r = f(true);
    EXPECT_TRUE(r.ok());
    EXPECT_EQ("apple", *r);

    auto s = f(false);
    EXPECT_FALSE(s.ok());
    EXPECT_EQ(PERMISSION_DENIED, s.error().code());
    EXPECT_EQ("PERMISSION_DENIED", s.error().message());
}

TEST(errors, unwrap_or_fatal) {
    status_t s = OR_FATAL(success_or_fail(true));
    EXPECT_EQ(OK, s);

    EXPECT_DEATH(OR_FATAL(success_or_fail(false)), "PERMISSION_DENIED");
}

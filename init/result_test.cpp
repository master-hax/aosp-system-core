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

#include "result.h"

#include "errno.h"

#include <string>

#include <gtest/gtest.h>

using namespace std::string_literals;

namespace android {
namespace init {

TEST(result, result_accessors) {
    auto result = Ok<std::string>("success");
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ("success", *result);
    EXPECT_EQ("success", result.value());

    EXPECT_EQ('s', result->data()[0]);
}

TEST(result, result_accessors_rvalue) {
    ASSERT_TRUE(Ok<std::string>("success"));
    ASSERT_TRUE(Ok<std::string>("success").has_value());

    EXPECT_EQ("success", *Ok<std::string>("success"));
    EXPECT_EQ("success", Ok<std::string>("success").value());

    EXPECT_EQ('s', Ok<std::string>("success")->data()[0]);
}

TEST(result, result_success) {
    Result<Success> result = Ok();
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(std::monostate(), *result);
    EXPECT_EQ(std::monostate(), result.value());
}

TEST(result, result_success_rvalue) {
    ASSERT_TRUE(Ok());
    ASSERT_TRUE(Ok().has_value());

    EXPECT_EQ(std::monostate(), *Ok());
    EXPECT_EQ(std::monostate(), Ok().value());
}

TEST(result, result_err) {
    Result<Success> result = Err() << "failure" << 1;
    ASSERT_FALSE(result);
    ASSERT_FALSE(result.has_value());

    EXPECT_EQ("failure1", result.error());
}

TEST(result, result_err_empty) {
    Result<Success> result = Err();
    ASSERT_FALSE(result);
    ASSERT_FALSE(result.has_value());

    EXPECT_EQ("", result.error());
}

TEST(result, result_err_rvalue) {
    // Err() and PErr() aren't actually used to create a Result<T> object.
    // Under the hood, they actually create an intermediate class that can be implicitly constructed
    // into a Result<T>.  This is needed both to create the ostream and because Err() itself, by
    // definition will not know what the type, T, of the underlying Result<T> object that it would
    // create is.

    auto MakeRvalueErrResult = []() -> Result<Success> { return Err() << "failure" << 1; };
    ASSERT_FALSE(MakeRvalueErrResult());
    ASSERT_FALSE(MakeRvalueErrResult().has_value());

    EXPECT_EQ("failure1", MakeRvalueErrResult().error());
}

TEST(result, result_perr) {
    errno = 6;
    Result<Success> result = PErr() << "failure" << 1;

    ASSERT_FALSE(result);
    ASSERT_FALSE(result.has_value());

    EXPECT_EQ("failure1: "s + strerror(errno), result.error());
}

TEST(result, one_parameter_constructor_explicit) {
    struct TakesString {
        explicit TakesString(const std::string& s) : s_(s) {}
        std::string s_;
    };
    auto result = Ok<TakesString>("success"s);
    ASSERT_TRUE(result);
    ASSERT_EQ("success", result->s_);
}

TEST(result, ok_constructor_forwarding) {
    auto result = Ok<std::string>(5, 'a');

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ("aaaaa", *result);
}

TEST(result, ok_template_deduction) {
    Result result1 = Ok<std::string>("success");
    auto result2 = Ok("success"s);
    std::string success = "success";
    auto result3 = Ok(success);

    ASSERT_TRUE(result1);
    ASSERT_TRUE(result2);
    ASSERT_TRUE(result3);

    EXPECT_EQ(*result1, *result2);
    EXPECT_EQ(*result1, *result3);
}

TEST(result, die_on_access_failed_result) {
    Result<std::string> result = Err();
    ASSERT_DEATH(*result, "");
}

TEST(result, die_on_get_error_succesful_result) {
    auto result = Ok("success"s);
    ASSERT_DEATH(result.error(), "");
}

}  // namespace init
}  // namespace android

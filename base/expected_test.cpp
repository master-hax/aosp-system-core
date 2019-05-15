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

#include "android-base/expected.h"

#include <cstdio>
#include <string>

#include <gtest/gtest.h>

using android::base::expected;
using android::base::unexpected;

typedef expected<int, int> exp_int;
typedef expected<double, double> exp_double;
typedef expected<std::string, std::string> exp_string;

struct T {
  int a;
  int b;
  T() = default;
  T(int a, int b) noexcept : a(a), b(b) {}
};
bool operator==(const T& x, const T& y) {
  return x.a == y.a && x.b == y.b;
}
bool operator!=(const T& x, const T& y) {
  return x.a != y.a || x.b != y.b;
}

struct E {
    std::string message;
    int cause;
    E(const std::string& message, int cause) : message(message), cause(cause) {}
};

typedef expected<T,E> exp_complex;

TEST(Expected, testDefaultConstructible) {
  exp_int e;
  EXPECT_TRUE(e.has_value());
  EXPECT_EQ(0, e.value());

  exp_complex e2;
  EXPECT_TRUE(e2.has_value());
  EXPECT_EQ(T(0,0), e2.value());
}

TEST(Expected, testCopyConstructible) {
  exp_int e;
  exp_int e2 = e;

  EXPECT_TRUE(e.has_value());
  EXPECT_TRUE(e2.has_value());
  EXPECT_EQ(0, e.value());
  EXPECT_EQ(0, e2.value());
}

TEST(Expected, testMoveConstructible) {
  exp_int e;
  exp_int e2 = std::move(e);

  EXPECT_TRUE(e.has_value());
  EXPECT_TRUE(e2.has_value());
  EXPECT_EQ(0, e.value());
  EXPECT_EQ(0, e2.value());
}

TEST(Expected, testCopyConstructibleFromConvertibleType) {
  exp_double e = 3.3f;
  exp_int e2 = e;

  EXPECT_TRUE(e.has_value());
  EXPECT_TRUE(e2.has_value());
  EXPECT_EQ(3.3f, e.value());
  EXPECT_EQ(3, e2.value());
}

TEST(Expected, testMoveConstructibleFromConvertibleType) {
  exp_double e = 3.3f;
  exp_int e2 = std::move(e);

  EXPECT_TRUE(e.has_value());
  EXPECT_TRUE(e2.has_value());
  EXPECT_EQ(3.3f, e.value());
  EXPECT_EQ(3, e2.value());
}

TEST(Expected, testConstructibleFromValue) {
  exp_int e = 3;
  exp_double e2 = 5.5f;
  exp_string e3 = std::string("hello");
  exp_complex e4 = T(10, 20);

  EXPECT_TRUE(e.has_value());
  EXPECT_TRUE(e2.has_value());
  EXPECT_TRUE(e3.has_value());
  EXPECT_TRUE(e4.has_value());
  EXPECT_EQ(3, e.value());
  EXPECT_EQ(5.5f, e2.value());
  EXPECT_EQ("hello", e3.value());
  EXPECT_EQ(T(10,20), e4.value());
}

TEST(Expected, testConstructibleFromConvertibleValue) {
  exp_int e = 3.3f; // double to int

  EXPECT_TRUE(e.has_value());
  EXPECT_EQ(3, e.value());
}

TEST(Expected, testConstructibleFromUnexpected) {
  exp_int::unexpected_type unexp = unexpected(10);
  exp_int e = unexp;

  exp_double::unexpected_type unexp2 = unexpected(10.5f);
  exp_double e2 = unexp2;

  exp_string::unexpected_type unexp3 = unexpected(std::string("error"));
  exp_string e3 = unexp3;

  EXPECT_FALSE(e.has_value());
  EXPECT_FALSE(e2.has_value());
  EXPECT_FALSE(e3.has_value());
  EXPECT_EQ(10, e.error());
  EXPECT_EQ(10.5f, e2.error());
  EXPECT_EQ("error", e3.error());
}

TEST(Expected, testMoveConstructibleFromUnexpected) {
  exp_int e = unexpected(10);
  exp_double e2 = unexpected(10.5f);
  exp_string e3 = unexpected(std::string("error"));

  EXPECT_FALSE(e.has_value());
  EXPECT_FALSE(e2.has_value());
  EXPECT_FALSE(e3.has_value());
  EXPECT_EQ(10, e.error());
  EXPECT_EQ(10.5f, e2.error());
  EXPECT_EQ("error", e3.error());
}

TEST(Expected, testDestructible) {
  bool destroyed = false;
  struct T {
    bool* flag_;
    T(bool* flag) : flag_(flag) {}
    ~T() { *flag_ = true; }
  };
  {
    expected<T, int> exp = T(&destroyed);
  }
  EXPECT_TRUE(destroyed);
}

TEST(Expected, testAssignable) {
  exp_int e = 10;
  exp_int e2 = 20;
  e = e2;

  EXPECT_EQ(20, e.value());
  EXPECT_EQ(20, e2.value());

  exp_int e3 = 10;
  exp_int e4 = 20;
  e3 = std::move(e4);

  EXPECT_EQ(20, e3.value());
  EXPECT_EQ(20, e4.value());
}

TEST(Expected, testAssignableFromValue) {
  exp_int e = 10;
  e = 20;
  EXPECT_EQ(20, e.value());

  exp_double e2 = 3.5f;
  e2 = 10.5f;
  EXPECT_EQ(10.5f, e2.value());

  exp_string e3 = "hello";
  e3 = "world";
  EXPECT_EQ("world", e3.value());
}

TEST(Expected, testAssignableFromUnexpected) {
  exp_int e = 10;
  e = unexpected(30);
  EXPECT_FALSE(e.has_value());
  EXPECT_EQ(30, e.error());

  exp_double e2 = 3.5f;
  e2 = unexpected(10.5f);
  EXPECT_FALSE(e2.has_value());
  EXPECT_EQ(10.5f, e2.error());

  exp_string e3 = "hello";
  e3 = unexpected("world");
  EXPECT_FALSE(e3.has_value());
  EXPECT_EQ("world", e3.error());
}

TEST(Expected, testEmplace) {
  struct T {
    int a;
    double b;
    T() {}
    T(int a, double b) noexcept : a(a), b(b) {}
  };
  expected<T, int> exp;
  T t = exp.emplace(3, 10.5f);

  EXPECT_TRUE(exp.has_value());
  EXPECT_EQ(3, t.a);
  EXPECT_EQ(10.5f, t.b);
}

TEST(Expected, testSwapExpectedExpected) {
  exp_int e = 10;
  exp_int e2 = 20;
  e.swap(e2);

  EXPECT_TRUE(e.has_value());
  EXPECT_TRUE(e2.has_value());
  EXPECT_EQ(20, e.value());
  EXPECT_EQ(10, e2.value());
}

TEST(Expected, testSwapUnexpectedUnexpected) {
  exp_int e = unexpected(10);
  exp_int e2 = unexpected(20);
  e.swap(e2);
  EXPECT_FALSE(e.has_value());
  EXPECT_FALSE(e2.has_value());
  EXPECT_EQ(20, e.error());
  EXPECT_EQ(10, e2.error());
}

TEST(Expected, testSwapExpectedUnepected) {
  exp_int e = 10;
  exp_int e2 = unexpected(30);
  e.swap(e2);
  EXPECT_FALSE(e.has_value());
  EXPECT_TRUE(e2.has_value());
  EXPECT_EQ(30, e.error());
  EXPECT_EQ(10, e2.value());
}

TEST(Expected, testDereference) {
  struct T {
    int a;
    double b;
    T() {}
    T(int a, double b) : a(a), b(b) {}
  };
  expected<T, int> exp = T(3, 10.5f);

  EXPECT_EQ(3, exp->a);
  EXPECT_EQ(10.5f, exp->b);

  EXPECT_EQ(3, (*exp).a);
  EXPECT_EQ(10.5f, (*exp).b);
}

TEST(Expected, testTest) {
  exp_int e = 10;
  EXPECT_TRUE(e);
  EXPECT_TRUE(e.has_value());

  exp_int e2 = unexpected(10);
  EXPECT_FALSE(e2);
  EXPECT_FALSE(e2.has_value());
}

TEST(Expected, testGetValue) {
  exp_int e = 10;
  EXPECT_EQ(10, e.value());
  EXPECT_EQ(10, e.value_or(20));

  exp_int e2 = unexpected(10);
  EXPECT_EQ(10, e2.error());
  EXPECT_EQ(20, e2.value_or(20));
}

TEST(Expected, testSameValues) {
  exp_int e = 10;
  exp_int e2 = 10;
  EXPECT_TRUE(e == e2);
  EXPECT_TRUE(e2 == e);
  EXPECT_FALSE(e != e2);
  EXPECT_FALSE(e2 != e);
}

TEST(Expected, testDifferentValues) {
  exp_int e = 10;
  exp_int e2 = 20;
  EXPECT_FALSE(e == e2);
  EXPECT_FALSE(e2 == e);
  EXPECT_TRUE(e != e2);
  EXPECT_TRUE(e2 != e);
}

TEST(Expected, testValueWithError) {
  exp_int e = 10;
  exp_int e2 = unexpected(10);
  EXPECT_FALSE(e == e2);
  EXPECT_FALSE(e2 == e);
  EXPECT_TRUE(e != e2);
  EXPECT_TRUE(e2 != e);
}

TEST(Expected, testSameErrors) {
  exp_int e = unexpected(10);
  exp_int e2 = unexpected(10);
  EXPECT_TRUE(e == e2);
  EXPECT_TRUE(e2 == e);
  EXPECT_FALSE(e != e2);
  EXPECT_FALSE(e2 != e);
}

TEST(Expected, testDifferentErrors) {
  exp_int e = unexpected(10);
  exp_int e2 = unexpected(20);
  EXPECT_FALSE(e == e2);
  EXPECT_FALSE(e2 == e);
  EXPECT_TRUE(e != e2);
  EXPECT_TRUE(e2 != e);
}

TEST(Expected, testCompareWithSameValue) {
  exp_int e = 10;
  int value = 10;
  EXPECT_TRUE(e == value);
  EXPECT_TRUE(value == e);
  EXPECT_FALSE(e != value);
  EXPECT_FALSE(value != e);
}

TEST(Expected, testCompareWithDifferentValue) {
  exp_int e = 10;
  int value = 20;
  EXPECT_FALSE(e == value);
  EXPECT_FALSE(value == e);
  EXPECT_TRUE(e != value);
  EXPECT_TRUE(value != e);
}

TEST(Expected, testCompareWithSameError) {
  exp_int e = unexpected(10);
  exp_int::unexpected_type error = 10;
  EXPECT_TRUE(e == error);
  EXPECT_TRUE(error == e);
  EXPECT_FALSE(e != error);
  EXPECT_FALSE(error != e);
}

TEST(Expected, testCompareWithDifferentError) {
  exp_int e = unexpected(10);
  exp_int::unexpected_type error = 20;
  EXPECT_FALSE(e == error);
  EXPECT_FALSE(error == e);
  EXPECT_TRUE(e != error);
  EXPECT_TRUE(error != e);
}

TEST(Expected, testDivideExample) {
  struct QR {
    int quotient;
    int remainder;
    QR(int q, int r) noexcept : quotient(q), remainder(r) {}
    bool operator==(const QR& rhs) const {
      return quotient == rhs.quotient && remainder == rhs.remainder;
    }
    bool operator!=(const QR& rhs) const {
      return quotient != rhs.quotient || remainder == rhs.remainder;
    }
  };

  struct Test {
    static expected<QR,E> divide(int x, int y) {
      if (y == 0) {
        return unexpected(E("divide by zero", -1));
      } else {
        return QR(x / y, x % y);
      }
    }
  };

  EXPECT_FALSE(Test::divide(10, 0));
  EXPECT_EQ("divide by zero", Test::divide(10, 0).error().message);
  EXPECT_EQ(-1, Test::divide(10, 0).error().cause);

  EXPECT_TRUE(Test::divide(10, 3));
  EXPECT_EQ(QR(3, 1), Test::divide(10, 3));
}

// int main(int argc, char** argv) {
//   testing::InitGoogleTest(&argc, argv);
//   return RUN_ALL_TESTS();
// }
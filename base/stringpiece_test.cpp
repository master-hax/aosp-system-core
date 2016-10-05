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

#include "android-base/stringpiece.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>
#include <set>
#include <unordered_set>

#include <android-base/string_view>

using android::base::StringPiece;
using android::base::StringPiece16;

using std::experimental::string_view;
using std::experimental::u16string_view;

TEST(StringPieceTest, CompareNonNullTerminatedPiece) {
  StringPiece a("hello world", 5);
  StringPiece b("hello moon", 5);
  EXPECT_EQ(a, b);

  StringPiece16 a16(u"hello world", 5);
  StringPiece16 b16(u"hello moon", 5);
  EXPECT_EQ(a16, b16);
}

TEST(StringPieceTest, PiecesHaveCorrectSortOrder) {
  std::string testing("testing");
  std::string banana("banana");
  std::string car("car");
  EXPECT_TRUE(StringPiece(testing) > StringPiece(banana));
  EXPECT_TRUE(StringPiece(testing) > StringPiece(car));
  EXPECT_TRUE(StringPiece(banana) < StringPiece(testing));
  EXPECT_TRUE(StringPiece(banana) < StringPiece(car));
  EXPECT_TRUE(StringPiece(car) < StringPiece(testing));
  EXPECT_TRUE(StringPiece(car) > StringPiece(banana));

  std::basic_string<char16_t> wtesting(u"testing");
  std::basic_string<char16_t> wbanana(u"banana");
  std::basic_string<char16_t> wcar(u"car");
  EXPECT_TRUE(StringPiece16(wtesting) > StringPiece16(wbanana));
  EXPECT_TRUE(StringPiece16(wtesting) > StringPiece16(wcar));
  EXPECT_TRUE(StringPiece16(wbanana) < StringPiece16(wtesting));
  EXPECT_TRUE(StringPiece16(wbanana) < StringPiece16(wcar));
  EXPECT_TRUE(StringPiece16(wcar) < StringPiece16(wtesting));
  EXPECT_TRUE(StringPiece16(wcar) > StringPiece16(wbanana));
}

TEST(StringPieceTest, ContainsOtherStringPiece) {
  StringPiece text("I am a leaf on the wind.");
  StringPiece startNeedle("I am");
  StringPiece endNeedle("wind.");
  StringPiece middleNeedle("leaf");
  StringPiece emptyNeedle("");
  StringPiece missingNeedle("soar");
  StringPiece longNeedle("This string is longer than the text.");

  EXPECT_TRUE(text.contains(startNeedle));
  EXPECT_TRUE(text.contains(endNeedle));
  EXPECT_TRUE(text.contains(middleNeedle));
  EXPECT_TRUE(text.contains(emptyNeedle));
  EXPECT_FALSE(text.contains(missingNeedle));
  EXPECT_FALSE(text.contains(longNeedle));

  StringPiece16 text16(u"I am a leaf on the wind.");
  StringPiece16 startNeedle16(u"I am");
  StringPiece16 endNeedle16(u"wind.");
  StringPiece16 middleNeedle16(u"leaf");
  StringPiece16 emptyNeedle16(u"");
  StringPiece16 missingNeedle16(u"soar");
  StringPiece16 longNeedle16(u"This string is longer than the text.");

  EXPECT_TRUE(text16.contains(startNeedle16));
  EXPECT_TRUE(text16.contains(endNeedle16));
  EXPECT_TRUE(text16.contains(middleNeedle16));
  EXPECT_TRUE(text16.contains(emptyNeedle16));
  EXPECT_FALSE(text16.contains(missingNeedle16));
  EXPECT_FALSE(text16.contains(longNeedle16));
}

TEST(StringPieceTest, KatiTests) {
  std::unordered_set<StringPiece, android::base::StringPieceHash<char>> sps;
  sps.insert(StringPiece("foo"));
  sps.insert(StringPiece("foo"));
  sps.insert(StringPiece("bar"));
  ASSERT_EQ(2U, sps.size());
  ASSERT_EQ(1U, sps.count(StringPiece("foo")));
  ASSERT_EQ(1U, sps.count(StringPiece("bar")));

  ASSERT_TRUE(StringPiece("hogefugahige") == StringPiece("hogefugahige"));
  ASSERT_TRUE(StringPiece("hogefugahoge") != StringPiece("hogefugahige"));
  ASSERT_TRUE(StringPiece("hogefugahige") != StringPiece("higefugahige"));
}

TEST(StringPieceTest, string_view_CompareNonNullTerminatedPiece) {
  string_view a("hello world", 5);
  string_view b("hello moon", 5);
  EXPECT_EQ(a, b);

  u16string_view a16(u"hello world", 5);
  u16string_view b16(u"hello moon", 5);
  EXPECT_EQ(a16, b16);
}

TEST(StringPieceTest, string_view_PiecesHaveCorrectSortOrder) {
  std::string testing("testing");
  std::string banana("banana");
  std::string car("car");
  EXPECT_TRUE(string_view(testing) > string_view(banana));
  EXPECT_TRUE(string_view(testing) > string_view(car));
  EXPECT_TRUE(string_view(banana) < string_view(testing));
  EXPECT_TRUE(string_view(banana) < string_view(car));
  EXPECT_TRUE(string_view(car) < string_view(testing));
  EXPECT_TRUE(string_view(car) > string_view(banana));

  std::basic_string<char16_t> wtesting(u"testing");
  std::basic_string<char16_t> wbanana(u"banana");
  std::basic_string<char16_t> wcar(u"car");
  EXPECT_TRUE(u16string_view(wtesting) > u16string_view(wbanana));
  EXPECT_TRUE(u16string_view(wtesting) > u16string_view(wcar));
  EXPECT_TRUE(u16string_view(wbanana) < u16string_view(wtesting));
  EXPECT_TRUE(u16string_view(wbanana) < u16string_view(wcar));
  EXPECT_TRUE(u16string_view(wcar) < u16string_view(wtesting));
  EXPECT_TRUE(u16string_view(wcar) > u16string_view(wbanana));
}

TEST(StringPieceTest, string_view_ContainsOtherStringPiece) {
  string_view text("I am a leaf on the wind.");
  string_view startNeedle("I am");
  string_view endNeedle("wind.");
  string_view middleNeedle("leaf");
  string_view emptyNeedle("");
  string_view missingNeedle("soar");
  string_view longNeedle("This string is longer than the text.");

  EXPECT_TRUE(text.find(startNeedle) != string_view::npos);
  EXPECT_TRUE(text.find(endNeedle) != string_view::npos);
  EXPECT_TRUE(text.find(middleNeedle) != string_view::npos);
  EXPECT_TRUE(text.find(emptyNeedle) != string_view::npos);
  EXPECT_FALSE(text.find(missingNeedle) != string_view::npos);
  EXPECT_FALSE(text.find(longNeedle) != string_view::npos);

  u16string_view text16(u"I am a leaf on the wind.");
  u16string_view startNeedle16(u"I am");
  u16string_view endNeedle16(u"wind.");
  u16string_view middleNeedle16(u"leaf");
  u16string_view emptyNeedle16(u"");
  u16string_view missingNeedle16(u"soar");
  u16string_view longNeedle16(u"This string is longer than the text.");

  EXPECT_TRUE(text16.find(startNeedle16) != u16string_view::npos);
  EXPECT_TRUE(text16.find(endNeedle16) != u16string_view::npos);
  EXPECT_TRUE(text16.find(middleNeedle16) != u16string_view::npos);
  EXPECT_TRUE(text16.find(emptyNeedle16) != u16string_view::npos);
  EXPECT_FALSE(text16.find(missingNeedle16) != u16string_view::npos);
  EXPECT_FALSE(text16.find(longNeedle16) != u16string_view::npos);
}

TEST(StringPieceTest, string_view_KatiTests) {
  std::unordered_set<string_view> sps;
  sps.insert(string_view("foo"));
  sps.insert(string_view("foo"));
  sps.insert(string_view("bar"));
  ASSERT_EQ(2U, sps.size());
  ASSERT_EQ(1U, sps.count(string_view("foo")));
  ASSERT_EQ(1U, sps.count(string_view("bar")));

  ASSERT_TRUE(string_view("hogefugahige") == string_view("hogefugahige"));
  ASSERT_TRUE(string_view("hogefugahoge") != string_view("hogefugahige"));
  ASSERT_TRUE(string_view("hogefugahige") != string_view("higefugahige"));
}

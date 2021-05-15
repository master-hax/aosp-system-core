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

#include <utils/String16.h>
#include <utils/String8.h>

#include <gtest/gtest.h>

using namespace android;

::testing::AssertionResult Char16_tStringEquals(const char16_t* a, const char16_t* b) {
    if (strcmp16(a, b) != 0) {
        return ::testing::AssertionFailure()
               << "\"" << String8(a).c_str() << "\" not equal to \"" << String8(b).c_str() << "\"";
    }
    return ::testing::AssertionSuccess();
}

#define EXPECT_STR16EQ(a, b) EXPECT_TRUE(Char16_tStringEquals(a, b))

TEST(String16Test, constructor) {
    EXPECT_STR16EQ(String16(), u"");

    // const char*
    EXPECT_STR16EQ(String16("Καλημέρα κόσμε"), String16("Καλημέρα κόσμε"));
    EXPECT_STR16EQ(String16("Καλημέρα κόσμε", 16), String16("Καλημέρα"));

    // String8
    EXPECT_STR16EQ(String16("Καλημέρα κόσμε"), String16(String8("Καλημέρα κόσμε")));

    // String16
    String16 hello_world("Καλημέρα κόσμε");
    EXPECT_STR16EQ(String16(hello_world).string(), String16("Καλημέρα κόσμε"));
    EXPECT_STR16EQ(String16(hello_world, 8).string(), String16("Καλημέρα"));
    EXPECT_STR16EQ(String16(hello_world, 5, 9).string(), String16("κόσμε"));

    // const char16_t*
    EXPECT_STR16EQ(String16(u"Καλημέρα κόσμε").string(), String16("Καλημέρα κόσμε"));
    EXPECT_STR16EQ(String16(u"Καλημέρα κόσμε", 8).string(), String16("Καλημέρα"));
    EXPECT_STR16EQ(String16(u"Καλημέρα κόσμε", 0).string(), String16(""));
    EXPECT_STR16EQ(String16(u"Καλημέρα κόσμε", SIZE_MAX / 2).string(), String16(""));
    EXPECT_STR16EQ(String16(u"Καλημέρα κόσμε", SIZE_MAX).string(), String16(""));
}

TEST(String16Test, append) {
    String16 s;
    EXPECT_EQ(OK, s.append(String16(u"foo")));
    EXPECT_STR16EQ(u"foo", s);
    EXPECT_EQ(OK, s.append(String16(u"bar")));
    EXPECT_STR16EQ(u"foobar", s);
    EXPECT_EQ(OK, s.append(u"baz", 0));
    EXPECT_STR16EQ(u"foobar", s);
    EXPECT_EQ(NO_MEMORY, s.append(u"baz", SIZE_MAX));
    EXPECT_STR16EQ(u"foobar", s);
}

TEST(String16Test, FromChar16_tSized) {
    String16 tmp(u"Verify me", 7);
    EXPECT_STR16EQ(u"Verify ", tmp);
}

TEST(String16Test, Copy) {
    String16 tmp("Verify me");
    String16 another = tmp;
    EXPECT_STR16EQ(u"Verify me", tmp);
    EXPECT_STR16EQ(u"Verify me", another);
}

TEST(String16Test, CopyAssign) {
    String16 tmp("Verify me");
    String16 another;
    another = tmp;
    EXPECT_STR16EQ(u"Verify me", tmp);
    EXPECT_STR16EQ(u"Verify me", another);
}

TEST(String16Test, Move) {
    String16 tmp("Verify me");
    String16 another(std::move(tmp));
    EXPECT_STR16EQ(u"Verify me", another);
}

TEST(String16Test, MoveAssign) {
    String16 tmp("Verify me");
    String16 another;
    another = std::move(tmp);
    EXPECT_STR16EQ(u"Verify me", another);
}

TEST(String16Test, Size) {
    String16 tmp("Verify me");
    EXPECT_EQ(9U, tmp.size());
}

TEST(String16Test, Append) {
    String16 tmp("Verify me");
    tmp.append(String16("Hello"));
    EXPECT_EQ(14U, tmp.size());
    EXPECT_STR16EQ(u"Verify meHello", tmp);
}

TEST(String16Test, Insert) {
    String16 tmp("Verify me");
    tmp.insert(6, u"Insert");
    EXPECT_EQ(15U, tmp.size());
    EXPECT_STR16EQ(u"VerifyInsert me", tmp);
}

TEST(String16Test, ReplaceAll) {
    String16 tmp("Verify verify Verify");
    tmp.replaceAll(u'r', u'!');
    EXPECT_STR16EQ(u"Ve!ify ve!ify Ve!ify", tmp);
}

TEST(String16Test, Compare) {
    String16 tmp("Verify me");
    EXPECT_EQ(String16(u"Verify me"), tmp);
}

TEST(String16Test, isStaticString) {
    String16 nonStaticString("NonStatic");
    StaticString16 staticString(u"Static");

    EXPECT_TRUE(staticString.isStaticString());
    EXPECT_FALSE(nonStaticString.isStaticString());
}

TEST(String16Test, StaticStringCopy) {
    StaticString16 tmp(u"Verify me");
    String16 another = tmp;
    EXPECT_STR16EQ(u"Verify me", tmp);
    EXPECT_STR16EQ(u"Verify me", another);
    EXPECT_TRUE(tmp.isStaticString());
    EXPECT_TRUE(another.isStaticString());
}

TEST(String16Test, StaticStringMove) {
    StaticString16 tmp(u"Verify me");
    String16 another(std::move(tmp));
    EXPECT_STR16EQ(u"Verify me", another);
    EXPECT_TRUE(another.isStaticString());
}

TEST(String16Test, StaticStringSize) {
    StaticString16 tmp(u"Verify me");
    EXPECT_EQ(9U, tmp.size());
}

TEST(String16Test, StaticStringAppend) {
    StaticString16 tmp(u"Verify me");
    tmp.append(String16("Hello"));
    EXPECT_EQ(14U, tmp.size());
    EXPECT_STR16EQ(u"Verify meHello", tmp);
    EXPECT_FALSE(tmp.isStaticString());
}

TEST(String16Test, StaticStringInsert) {
    StaticString16 tmp(u"Verify me");
    tmp.insert(6, u"Insert");
    EXPECT_EQ(15U, tmp.size());
    EXPECT_STR16EQ(u"VerifyInsert me", tmp);
    EXPECT_FALSE(tmp.isStaticString());
}

TEST(String16Test, StaticStringReplaceAll) {
    StaticString16 tmp(u"Verify verify Verify");
    tmp.replaceAll(u'r', u'!');
    EXPECT_STR16EQ(u"Ve!ify ve!ify Ve!ify", tmp);
    EXPECT_FALSE(tmp.isStaticString());
}

TEST(String16Test, StaticStringCompare) {
    StaticString16 tmp(u"Verify me");
    EXPECT_EQ(String16(u"Verify me"), tmp);
}

TEST(String16Test, StringSetToStaticString) {
    StaticString16 tmp(u"Verify me");
    String16 another(u"nonstatic");
    another = tmp;
    EXPECT_STR16EQ(u"Verify me", tmp);
    EXPECT_STR16EQ(u"Verify me", another);
}

TEST(String16Test, StringCopyAssignFromStaticString) {
    StaticString16 tmp(u"Verify me");
    String16 another(u"nonstatic");
    another = tmp;
    EXPECT_STR16EQ(u"Verify me", another);
    EXPECT_TRUE(another.isStaticString());
    EXPECT_STR16EQ(u"Verify me", tmp);
    EXPECT_TRUE(tmp.isStaticString());
}

TEST(String16Test, StringMoveAssignFromStaticString) {
    StaticString16 tmp(u"Verify me");
    String16 another(u"nonstatic");
    another = std::move(tmp);
    EXPECT_STR16EQ(u"Verify me", another);
    EXPECT_TRUE(another.isStaticString());
}

TEST(String16Test, EmptyStringIsStatic) {
    String16 tmp("");
    EXPECT_TRUE(tmp.isStaticString());
}

TEST(String16Test, OverreadUtf8Conversion) {
    char tmp[] = {'a', static_cast<char>(0xe0), '\0'};
    String16 another(tmp);
    EXPECT_TRUE(another.size() == 0);
}

TEST(String16Test, ValidUtf8Conversion) {
    String16 another("abcdef");
    EXPECT_EQ(6U, another.size());
    EXPECT_STR16EQ(another, u"abcdef");
}

TEST(String16Test, compare) {
    EXPECT_TRUE(String16("hello").compare(String16("world")) < 0);
    EXPECT_TRUE(String16("hello").compare(String16("hello")) == 0);
    EXPECT_TRUE(String16("world").compare(String16("hello")) > 0);
}

TEST(String16Test, compare_type) {
    EXPECT_TRUE(compare_type(String16("hello"), String16("world")) < 0);
    EXPECT_TRUE(compare_type(String16("hello"), String16("hello")) == 0);
    EXPECT_TRUE(compare_type(String16("world"), String16("hello")) > 0);
}

TEST(String16Test, strictly_order_type) {
    EXPECT_TRUE(strictly_order_type(String16("hello"), String16("world")));
    EXPECT_FALSE(strictly_order_type(String16("hello"), String16("hello")));
    EXPECT_FALSE(strictly_order_type(String16("world"), String16("hello")));
}

TEST(String16Test, comparisons_String16) {
    EXPECT_TRUE(String16("hello") < String16("world"));
    EXPECT_TRUE(String16("hello") <= String16("hello"));
    EXPECT_TRUE(String16("hello") == String16("hello"));
    EXPECT_TRUE(String16("hello") != String16("world"));
    EXPECT_TRUE(String16("world") >= String16("world"));
    EXPECT_TRUE(String16("world") > String16("hello"));

    EXPECT_FALSE(String16("world") < String16("hello"));
    EXPECT_FALSE(String16("world") <= String16("hello"));
    EXPECT_FALSE(String16("world") == String16("hello"));
    EXPECT_FALSE(String16("world") != String16("world"));
    EXPECT_FALSE(String16("hello") >= String16("world"));
    EXPECT_FALSE(String16("hello") > String16("hello"));
}

TEST(String16Test, comparisons_const_char16_star) {
    EXPECT_TRUE(String16("hello") < u"world");
    EXPECT_TRUE(String16("hello") <= u"hello");
    EXPECT_TRUE(String16("hello") == u"hello");
    EXPECT_TRUE(String16("hello") != u"world");
    EXPECT_TRUE(String16("world") >= u"world");
    EXPECT_TRUE(String16("world") > u"hello");

    EXPECT_FALSE(String16("world") < u"hello");
    EXPECT_FALSE(String16("world") <= u"hello");
    EXPECT_FALSE(String16("world") == u"hello");
    EXPECT_FALSE(String16("world") != u"world");
    EXPECT_FALSE(String16("hello") >= u"world");
    EXPECT_FALSE(String16("hello") > u"hello");
}

TEST(String16Test, operator_plus) {
    String16 src1("Hello, ");

    String16 src2("world!");
    String16 dst2 = src1 + src2;
    EXPECT_STR16EQ(dst2.string(), u"Hello, world!");
    EXPECT_STR16EQ(src1.string(), u"Hello, ");
    EXPECT_STR16EQ(src2.string(), u"world!");
}

TEST(String16Test, operator_plus_equals) {
    String16 src1("My voice");

    String16 src2(" is my passport.");
    src1 += src2;
    EXPECT_STR16EQ(src1.string(), u"My voice is my passport.");
    EXPECT_STR16EQ(src2.string(), u" is my passport.");
}

TEST(String16Test, contains) {
    EXPECT_TRUE(String16("hello world").contains(u"hello world"));
    EXPECT_TRUE(String16("hello world").contains(u"hello"));
    EXPECT_TRUE(String16("hello world").contains(u"lo wo"));
    EXPECT_TRUE(String16("hello world").contains(u"world"));

    EXPECT_FALSE(String16("hello world").contains(u"lll"));
}

TEST(String16Test, startsWith) {
    EXPECT_FALSE(String16("Καλημέρα κόσμε").startsWith(String16("Καλημέρα κόσμε!")));
    EXPECT_TRUE(String16("Καλημέρα κόσμε").startsWith(String16("Καλημέρα κόσμε")));
    EXPECT_TRUE(String16("Καλημέρα κόσμε").startsWith(String16("Καλημέρα")));
    EXPECT_TRUE(String16("Καλημέρα κόσμε").startsWith(String16("")));

    EXPECT_FALSE(String16("Καλημέρα κόσμε").startsWith(u"Καλημέρα κόσμε!"));
    EXPECT_TRUE(String16("Καλημέρα κόσμε").startsWith(u"Καλημέρα κόσμε"));
    EXPECT_TRUE(String16("Καλημέρα κόσμε").startsWith(u"Καλημέρα"));
    EXPECT_TRUE(String16("Καλημέρα κόσμε").startsWith(u""));
}

TEST(String16Test, findFirst) {
    EXPECT_EQ(0, String16("Καλημέρα κόσμε").findFirst(u'Κ'));
    EXPECT_EQ(2, String16("Καλημέρα κόσμε").findFirst(u'λ'));
    EXPECT_EQ(13, String16("Καλημέρα κόσμε").findFirst(u'ε'));
    EXPECT_EQ(-1, String16("Καλημέρα κόσμε").findFirst(u'a'));

    EXPECT_EQ(13, String16("Καλημέρα κόσμε").findLast(u'ε'));
    EXPECT_EQ(12, String16("Καλημέρα κόσμε").findLast(u'μ'));
    EXPECT_EQ(0, String16("Καλημέρα κόσμε").findLast(u'Κ'));
    EXPECT_EQ(-1, String16("Καλημέρα κόσμε").findLast(u'K'));
}

TEST(String16Test, setTo) {
    String16 s;
    EXPECT_EQ(OK, s.setTo(u"some long string"));
    EXPECT_STR16EQ(u"some long string", s);
    EXPECT_EQ(OK, s.setTo(u"some even longer string"));
    EXPECT_STR16EQ(u"some even longer string", s);
    EXPECT_EQ(OK, s.setTo(u"shorter string"));
    EXPECT_STR16EQ(u"shorter string", s);

    EXPECT_EQ(NO_MEMORY, s.setTo(u"blah", SIZE_MAX));
    EXPECT_STR16EQ(u"", s);

    EXPECT_EQ(OK, s.setTo(u"some string", 11));
    EXPECT_EQ(NO_MEMORY, s.setTo(u"blah", SIZE_MAX));
    EXPECT_STR16EQ(u"", s);

    // setTo with begin > the length of the other string yields the empty string.
    s = String16("foo");
    EXPECT_EQ(OK, s.setTo(String16("some string"), 11, 11));
    EXPECT_STR16EQ(u"", s);
    // Otherwise you get as much of the other string as there is, if you ask for too much.
    EXPECT_EQ(OK, s.setTo(String16("some string"), 11, 5));
    EXPECT_STR16EQ(u"string", s);
    // And there's a special case for the whole of the other string.
    EXPECT_EQ(OK, s.setTo(String16("some string"), 11, 0));
    EXPECT_STR16EQ(u"some string", s);

    EXPECT_EQ(OK, s.setTo(String16("some string"), 9, 1));
    EXPECT_STR16EQ(u"ome strin", s);
}

TEST(String16Test, StaticString16_setTo_shorter) {
    StaticString16 s(u"some long string");
    EXPECT_EQ(OK, s.setTo(u"shorter"));
    EXPECT_STR16EQ(u"shorter", s);
}

TEST(String16Test, insert) {
    String16 s;

    // Inserting into the empty string inserts at the start.
    EXPECT_EQ(OK, s.insert(123, u"foo"));
    EXPECT_STR16EQ(u"foo", s);

    // Inserting zero characters at any position is okay, but won't expand the string.
    EXPECT_EQ(OK, s.insert(123, u"foo", 0));
    EXPECT_STR16EQ(u"foo", s);

    // Inserting past the end of a non-empty string appends.
    EXPECT_EQ(OK, s.insert(123, u"bar"));
    EXPECT_STR16EQ(u"foobar", s);

    EXPECT_EQ(OK, s.insert(3, u"!"));
    EXPECT_STR16EQ(u"foo!bar", s);

    EXPECT_EQ(NO_MEMORY, s.insert(3, u"", SIZE_MAX));
    EXPECT_STR16EQ(u"foo!bar", s);
}

TEST(String16Test, operator_out) {
    std::stringstream ss;
    ss << String16("hello world");
    EXPECT_EQ("hello world", ss.str());
}

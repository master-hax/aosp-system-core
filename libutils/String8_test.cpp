/*
 * Copyright (C) 2010 The Android Open Source Project
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

#define LOG_TAG "String8_test"

#include <utils/Log.h>
#include <utils/String8.h>
#include <utils/String16.h>

#include <gtest/gtest.h>

using namespace android;

TEST(String8Test, constructor) {
    EXPECT_STREQ(String8().string(), "");

    // const char*
    EXPECT_STREQ(String8("Καλημέρα κόσμε").string(), "Καλημέρα κόσμε");
    EXPECT_STREQ(String8("Καλημέρα κόσμε", 16).string(), "Καλημέρα");

    // String16
    EXPECT_STREQ(String8(String16("Καλημέρα κόσμε")).string(), "Καλημέρα κόσμε");

    // char16_t
    EXPECT_STREQ(String8(u"Καλημέρα κόσμε").string(), "Καλημέρα κόσμε");
    EXPECT_STREQ(String8(u"Καλημέρα κόσμε", 8).string(), "Καλημέρα");
    EXPECT_STREQ(String8(u"Καλημέρα κόσμε", 0).string(), "");

    // char32_t
    EXPECT_STREQ(String8(U"Καλημέρα κόσμε").string(), "Καλημέρα κόσμε");
    EXPECT_STREQ(String8(U"Καλημέρα κόσμε", 8).string(), "Καλημέρα");
    EXPECT_STREQ(String8(U"Καλημέρα κόσμε", 0).string(), "");
}

TEST(String8Test, format) {
    EXPECT_STREQ(String8::format("%s, %s!", "hello", "world"), "hello, world!");
}

TEST(String8Test, append) {
    String8 s;
    EXPECT_EQ(OK, s.append("foo"));
    EXPECT_STREQ("foo", s);
    EXPECT_EQ(OK, s.append("bar"));
    EXPECT_STREQ("foobar", s);
    EXPECT_EQ(OK, s.append("baz", 0));
    EXPECT_STREQ("foobar", s);
    EXPECT_EQ(NO_MEMORY, s.append("baz", SIZE_MAX));
    EXPECT_STREQ("foobar", s);
}

TEST(String8Test, appendFormat) {
    String8 s;
    s.appendFormat("%s, ", "hello");
    s.appendFormat("%s!", "world");
    EXPECT_STREQ(s, "hello, world!");
}

TEST(String8Test, size) {
    EXPECT_EQ(16u, String8("Καλημέρα").size());
    EXPECT_EQ(16u, String8(u"Καλημέρα").size());
    EXPECT_EQ(16u, String8(U"Καλημέρα").size());
}

TEST(String8Test, conversions) {
    String8 s("foo");
    EXPECT_STREQ("foo", s.c_str());
    EXPECT_STREQ("foo", s.string());
    EXPECT_EQ(s.c_str(), s.string());
}

TEST(String8Test, isEmpty) {
    EXPECT_TRUE(String8("").isEmpty());
    EXPECT_FALSE(String8("Καλημέρα").isEmpty());

    EXPECT_TRUE(String8(u"").isEmpty());
    EXPECT_FALSE(String8(u"Καλημέρα").isEmpty());

    EXPECT_TRUE(String8(U"").isEmpty());
    EXPECT_FALSE(String8(U"Καλημέρα").isEmpty());
}

TEST(String8Test, empty) {
    EXPECT_STREQ("", String8::empty());
}

TEST(String8Test, find) {
    EXPECT_EQ(0, String8("hello world").find("hello"));
    EXPECT_EQ(3, String8("hello world").find("lo wo"));
    EXPECT_EQ(6, String8("hello world").find("world"));

    EXPECT_EQ(-1, String8("hello world").find("lll"));

    EXPECT_EQ(6, String8("hello hello").find("hello", 1));
    EXPECT_EQ(-1, String8("hello hello").find("hello", 128));
}

TEST(String8Test, contains) {
    EXPECT_TRUE(String8("hello world").contains("hello world"));
    EXPECT_TRUE(String8("hello world").contains("hello"));
    EXPECT_TRUE(String8("hello world").contains("lo wo"));
    EXPECT_TRUE(String8("hello world").contains("world"));

    EXPECT_FALSE(String8("hello world").contains("lll"));
}

TEST(String8Test, compare) {
    EXPECT_TRUE(String8("hello").compare(String8("world")) < 0);
    EXPECT_TRUE(String8("hello").compare(String8("hello")) == 0);
    EXPECT_TRUE(String8("world").compare(String8("hello")) > 0);
}

TEST(String8Test, compare_type) {
    EXPECT_TRUE(compare_type(String8("hello"), String8("world")) < 0);
    EXPECT_TRUE(compare_type(String8("hello"), String8("hello")) == 0);
    EXPECT_TRUE(compare_type(String8("world"), String8("hello")) > 0);
}

TEST(String8Test, strictly_order_type) {
    EXPECT_TRUE(strictly_order_type(String8("hello"), String8("world")));
    EXPECT_FALSE(strictly_order_type(String8("hello"), String8("hello")));
    EXPECT_FALSE(strictly_order_type(String8("world"), String8("hello")));
}

TEST(String8Test, comparisons_String8) {
    EXPECT_TRUE(String8("hello") < String8("world"));
    EXPECT_TRUE(String8("hello") <= String8("hello"));
    EXPECT_TRUE(String8("hello") == String8("hello"));
    EXPECT_TRUE(String8("hello") != String8("world"));
    EXPECT_TRUE(String8("world") >= String8("world"));
    EXPECT_TRUE(String8("world") > String8("hello"));

    EXPECT_FALSE(String8("world") < String8("hello"));
    EXPECT_FALSE(String8("world") <= String8("hello"));
    EXPECT_FALSE(String8("world") == String8("hello"));
    EXPECT_FALSE(String8("world") != String8("world"));
    EXPECT_FALSE(String8("hello") >= String8("world"));
    EXPECT_FALSE(String8("hello") > String8("hello"));
}

TEST(String8Test, comparisons_const_char_star) {
    EXPECT_TRUE(String8("hello") < "world");
    EXPECT_TRUE(String8("hello") <= "hello");
    EXPECT_TRUE(String8("hello") == "hello");
    EXPECT_TRUE(String8("hello") != "world");
    EXPECT_TRUE(String8("world") >= "world");
    EXPECT_TRUE(String8("world") > "hello");

    EXPECT_FALSE(String8("world") < "hello");
    EXPECT_FALSE(String8("world") <= "hello");
    EXPECT_FALSE(String8("world") == "hello");
    EXPECT_FALSE(String8("world") != "world");
    EXPECT_FALSE(String8("hello") >= "world");
    EXPECT_FALSE(String8("hello") > "hello");
}

TEST(String8Test, operator_equals) {
    String8 s;
    s = "hello";
    EXPECT_STREQ("hello", s);
    s = String8("goodbye");
    EXPECT_STREQ("goodbye", s);
}

TEST(String8Test, clear) {
    String8 s("foo");
    EXPECT_STREQ("foo", s);
    s.clear();
    EXPECT_STREQ("", s);
    EXPECT_TRUE(s.isEmpty());
}

TEST(String8Test, setTo) {
    String8 s;
    EXPECT_EQ(OK, s.setTo("some string"));
    EXPECT_STREQ("some string", s);

    EXPECT_EQ(NO_MEMORY, s.setTo("blah", SIZE_MAX));
    EXPECT_TRUE(s.isEmpty());

    EXPECT_EQ(OK, s.setTo(u"some string", 11));
    EXPECT_EQ(NO_MEMORY, s.setTo(u"blah", SIZE_MAX));
    EXPECT_TRUE(s.isEmpty());

    EXPECT_EQ(OK, s.setTo(U"some string", 11));
    EXPECT_EQ(NO_MEMORY, s.setTo(U"blah", SIZE_MAX));
    EXPECT_TRUE(s.isEmpty());
}

TEST(String8Test, lockBuffer_unlockBuffer) {
    String8 s;
    strcpy(s.lockBuffer(128), "hello");
    EXPECT_EQ(OK, s.unlockBuffer(5));
    EXPECT_STREQ("hello", s.c_str());
    EXPECT_EQ(nullptr, s.lockBuffer(SIZE_MAX));
    EXPECT_EQ(NO_MEMORY, s.unlockBuffer(SIZE_MAX));
    s.unlockBuffer();
}

TEST(String8Test, toLower) {
    String8 s;
    s.toLower();
    EXPECT_STREQ(s.c_str(), "");
    // String8::toLower is ASCII-only...
    s = "Καλημέρα κόσμε";
    s.toLower();
    EXPECT_STREQ(s.c_str(), "Καλημέρα κόσμε");
    // ...but at least doesn't corrupt non-ASCII.
    s = "HELLO, World!";
    s.toLower();
    EXPECT_STREQ(s.c_str(), "hello, world!");
}

TEST(String8Test, removeAll) {
    String8 s;
    EXPECT_FALSE(s.removeAll("foo"));
    s = "hefoollfooo fooworldfoo";
    EXPECT_TRUE(s.removeAll("foo"));
    EXPECT_STREQ("hello world", s);
}

TEST(String8Test, operator_plus) {
    String8 src1("Hello, ");

    // Test adding String8 + const char*
    const char* ccsrc2 = "world!";
    String8 dst1 = src1 + ccsrc2;
    EXPECT_STREQ(dst1.string(), "Hello, world!");
    EXPECT_STREQ(src1.string(), "Hello, ");
    EXPECT_STREQ(ccsrc2, "world!");

    // Test adding String8 + String8
    String8 ssrc2("world!");
    String8 dst2 = src1 + ssrc2;
    EXPECT_STREQ(dst2.string(), "Hello, world!");
    EXPECT_STREQ(src1.string(), "Hello, ");
    EXPECT_STREQ(ssrc2.string(), "world!");
}

TEST(String8Test, operator_plus_equals) {
    String8 src1("My voice");

    // Testing String8 += String8
    String8 src2(" is my passport.");
    src1 += src2;
    EXPECT_STREQ(src1.string(), "My voice is my passport.");
    EXPECT_STREQ(src2.string(), " is my passport.");

    // Adding const char* to the previous string.
    const char* src3 = " Verify me.";
    src1 += src3;
    EXPECT_STREQ(src1.string(), "My voice is my passport. Verify me.");
    EXPECT_STREQ(src2.string(), " is my passport.");
    EXPECT_STREQ(src3, " Verify me.");
}

// http://b/29250543
TEST(String8Test, CorrectInvalidSurrogate) {
    // d841d8 is an invalid start for a surrogate pair. Make sure this is handled by ignoring the
    // first character in the pair and handling the rest correctly.
    String16 string16(u"\xd841\xd841\xdc41\x0000");
    String8 string8(string16);
    EXPECT_EQ(4U, string8.length());
}

TEST(String8Test, CheckUtf32Conversion) {
    // Since bound checks were added, check the conversion can be done without fatal errors.
    // The utf8 lengths of these are chars are 1 + 2 + 3 + 4 = 10.
    const char32_t string32[] = U"\x0000007f\x000007ff\x0000911\x0010fffe";
    String8 string8(string32);
    EXPECT_EQ(10U, string8.length());
}

TEST(String8Test, setPathName) {
    String8 s;
    s.setPathName("/foo");
    EXPECT_STREQ("/foo", s.c_str());
    s.setPathName("/foo/");
    EXPECT_STREQ("/foo", s.c_str());
    // But this is pretty stupid...
    s.setPathName("/foo//");
    EXPECT_STREQ("/foo/", s.c_str());
    // Actually, it gets worse...
    s.setPathName("/");
    EXPECT_STREQ("", s.c_str());
}

TEST(String8Test, getPathDir) {
    EXPECT_STREQ("/tmp/foo", String8("/tmp/foo/bar.c").getPathDir());
    EXPECT_STREQ("", String8("/tmp").getPathDir());
    EXPECT_STREQ("", String8("bar.c").getPathDir());
}

TEST(String8Test, getPathLeaf) {
    EXPECT_STREQ("bar.c", String8("/tmp/foo/bar.c").getPathLeaf());
    EXPECT_STREQ("bar.c", String8("bar.c").getPathLeaf());
}

TEST(String8Test, getPathExtension) {
    EXPECT_STREQ("", String8("no-extension").getPathExtension());
    EXPECT_STREQ("", String8("/usr.bin/no-extension").getPathExtension());
    EXPECT_STREQ(".blah", String8("/usr.bin/some-extension.blah").getPathExtension());
}

TEST(String8Test, getBasePath) {
    EXPECT_STREQ("/tmp/foo/bar", String8("/tmp/foo/bar.c").getBasePath());
    EXPECT_STREQ("/tmp/foo/bar", String8("/tmp/foo/bar").getBasePath());
}

TEST(String8Test, appendPath) {
    String8 s;
    s.appendPath("/usr");
    EXPECT_STREQ("/usr", s.c_str());
    s.appendPath("");
    EXPECT_STREQ("/usr", s.c_str());
    s.appendPath("lib");
    EXPECT_STREQ("/usr/lib", s.c_str());
    s.appendPath("/etc");
    EXPECT_STREQ("/etc", s.c_str());

    // This seems unintentional, but we should preserve the behavior until we can remove this API.
    s.clear();
    s.appendPath("etc");
    EXPECT_STREQ("etc", s.c_str());

    s.appendPath(String8("init.d"));
    EXPECT_STREQ("etc/init.d", s.c_str());
}

TEST(String8Test, appendPathCopy) {
    String8 s("/usr");
    EXPECT_STREQ("/usr/lib", s.appendPathCopy("lib").c_str());
    EXPECT_STREQ("/usr/lib", s.appendPathCopy(String8("lib")).c_str());
    EXPECT_STREQ("/usr", s.c_str());
}

TEST(String8Test, walkPath) {
    String8 remain;
    EXPECT_STREQ("tmp", String8("/tmp/foo/bar.c").walkPath(&remain));
    EXPECT_STREQ("foo/bar.c", remain);

    EXPECT_STREQ("tmp", String8("/tmp").walkPath(&remain));
    EXPECT_STREQ("", remain);

    EXPECT_STREQ("bar.c", String8("bar.c").walkPath(&remain));
    EXPECT_STREQ("", remain);
}

TEST(String8Test, convertToResPath) {
    EXPECT_STREQ("/foo/bar", String8("/foo/bar").convertToResPath());
}

TEST(String8Test, operator_out) {
    std::stringstream ss;
    ss << String8("hello world");
    EXPECT_EQ("hello world", ss.str());
}

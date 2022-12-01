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

#define LOG_TAG "Unicode_test"

#include <sys/mman.h>
#include <unistd.h>

#include <log/log.h>
#include <utils/Unicode.h>

#include <gtest/gtest.h>

namespace android {

class UnicodeTest : public testing::Test {
protected:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

    char16_t const * const kSearchString = u"I am a leaf on the wind.";
};

TEST_F(UnicodeTest, UTF8toUTF16ZeroLength) {
    ssize_t measured;

    const uint8_t str[] = { };

    measured = utf8_to_utf16_length(str, 0);
    EXPECT_EQ(0, measured)
            << "Zero length input should return zero length output.";
}

TEST_F(UnicodeTest, UTF8toUTF16ASCIILength) {
    ssize_t measured;

    // U+0030 or ASCII '0'
    const uint8_t str[] = { 0x30 };

    measured = utf8_to_utf16_length(str, sizeof(str));
    EXPECT_EQ(1, measured)
            << "ASCII glyphs should have a length of 1 char16_t";
}

TEST_F(UnicodeTest, UTF8toUTF16Plane1Length) {
    ssize_t measured;

    // U+2323 SMILE
    const uint8_t str[] = { 0xE2, 0x8C, 0xA3 };

    measured = utf8_to_utf16_length(str, sizeof(str));
    EXPECT_EQ(1, measured)
            << "Plane 1 glyphs should have a length of 1 char16_t";
}

TEST_F(UnicodeTest, UTF8toUTF16SurrogateLength) {
    ssize_t measured;

    // U+10000
    const uint8_t str[] = { 0xF0, 0x90, 0x80, 0x80 };

    measured = utf8_to_utf16_length(str, sizeof(str));
    EXPECT_EQ(2, measured)
            << "Surrogate pairs should have a length of 2 char16_t";
}

TEST_F(UnicodeTest, UTF8toUTF16TruncatedUTF8) {
    ssize_t measured;

    // Truncated U+2323 SMILE
    // U+2323 SMILE
    const uint8_t str[] = { 0xE2, 0x8C };

    measured = utf8_to_utf16_length(str, sizeof(str));
    EXPECT_EQ(-1, measured)
            << "Truncated UTF-8 should return -1 to indicate invalid";
}

TEST_F(UnicodeTest, UTF8toUTF16Normal) {
    const uint8_t str[] = {
        0x30,                   // U+0030, 1 UTF-16 character
        0xC4, 0x80,             // U+0100, 1 UTF-16 character
        0xE2, 0x8C, 0xA3,       // U+2323, 1 UTF-16 character
        0xF0, 0x90, 0x80, 0x80, // U+10000, 2 UTF-16 character
    };

    char16_t output[1 + 1 + 1 + 2 + 1];  // Room for null

    utf8_to_utf16(str, sizeof(str), output, std::size(output));

    EXPECT_EQ(0x0030, output[0]) << "should be U+0030";
    EXPECT_EQ(0x0100, output[1]) << "should be U+0100";
    EXPECT_EQ(0x2323, output[2]) << "should be U+2323";
    EXPECT_EQ(0xD800, output[3]) << "should be first half of surrogate U+10000";
    EXPECT_EQ(0xDC00, output[4]) << "should be second half of surrogate U+10000";
    EXPECT_EQ(0, output[5]) << "should be null terminated";
}

TEST_F(UnicodeTest, UTF8toUTF16Invalid) {
    const uint8_t str[] = {
        0xf8,                   // invalid leading byte
        0xc4, 0x00,             // U+0100 with invalid trailing byte
        0xe2, 0x0c, 0x23,       // U+2323 with invalid trailing bytes
        0xf0, 0x10, 0x00, 0x00, // U+10000 with invalid trailing bytes
    };
    char16_t output[1 + 1 + 1 + 2 + 1]; // Room for null

    // invalid input shouldn't crash this test
    utf8_to_utf16(str, sizeof(str), output, std::size(output));

    // invalid leading byte will be ignored and an invalid UTF-16 character
    // 0xFFFF will be produced in the output
    EXPECT_EQ(0xFFFF, output[0]) << "should be U+FFFF";

    // invalid trailing byte(s) will be ignored
    EXPECT_EQ(0x0100, output[1]) << "should be U+0100";
    EXPECT_EQ(0x2323, output[2]) << "should be U+2323";
    EXPECT_EQ(0xD800, output[3]) << "should be first half of surrogate U+10000";
    EXPECT_EQ(0xDC00, output[4]) << "should be second half of surrogate U+10000";
    EXPECT_EQ(0, output[5]) << "should be null terminated";
}

TEST_F(UnicodeTest, UTF16toUTF8ZeroLength) {
    ssize_t measured;

    const char16_t str[] = {};
    measured = utf16_to_utf8_length(str, 0);
    EXPECT_EQ(0, measured)
            << "Zero length input should return zero length output.";
}

TEST_F(UnicodeTest, UTF16toUTF8ASCIILength) {
    ssize_t measured;

    const char16_t str[] = { 0x0030 };

    measured = utf16_to_utf8_length(str, 1);
    EXPECT_EQ(1, measured)
            << "ASCII glyphs in UTF16 should give a length of 1 in UTF8";
}

TEST_F(UnicodeTest, UTF16toUTF8Plane1Length) {
    ssize_t measured;

    // U+2323 SMILE
    const char16_t str[] = { 0x2323 };

    measured = utf16_to_utf8_length(str, 1);
    EXPECT_EQ(3, measured)
            << "Plane 1 glyphs should have a length of 3 char in UTF-8";
}

TEST_F(UnicodeTest, UTF16toUTF8SurrogateLength) {
    ssize_t measured;

    // U+10000
    const char16_t str[] = { 0xd800, 0xdc00 };

    measured = utf16_to_utf8_length(str, 2);
    EXPECT_EQ(4, measured)
            << "Surrogate pairs should have a length of 4 chars";
}

TEST_F(UnicodeTest, UTF16toUTF8UnpairedSurrogateLength) {
    ssize_t measured;

    // U+10000 (but with half surrogate pair)
    const char16_t str[] = { 0xd800 };

    // the half surrogate will be converted as a normal 3-byte UTF8
    measured = utf16_to_utf8_length(str, 1);
    EXPECT_EQ(0, measured)
            << "A single unpaired surrogate should have a length of 0 chars";

    // U+0030, U+0100, U+10000 (but with half surrogate pair), U+2323
    const char16_t str2[] = { 0x0030, 0x0100, 0xd800, 0x2323 };
    measured = utf16_to_utf8_length(str2, 4);
    EXPECT_EQ(6, measured)
            << "Unpaired surrogate should be skipped";
}

TEST_F(UnicodeTest, UTF16toUTF8CorrectInvalidSurrogateLength) {
    ssize_t measured;

    // http://b/29250543
    // d841d8 is an invalid start for a surrogate pair. Make sure this is handled by ignoring the
    // first character in the pair and handling the rest correctly.
    const char16_t str[] = { 0xd841, 0xd841, 0xdc41 };

    measured = utf16_to_utf8_length(str, 3);
    EXPECT_EQ(4, measured)
            << "Surrogate pairs should have a length of 4 chars";
}

TEST_F(UnicodeTest, UTF16toUTF8Normal) {
    const char16_t str[] = {
        0x0024, // U+0024 ($) --> 0x24,           1 UTF-8 character
        0x00A3, // U+00A3 (£) --> 0xC2 0xA3,      2 UTF-8 characters
        0x0939, // U+0939 (ह) --> 0xE0 0xA4 0xB9, 3 UTF-8 characters
        0x20AC, // U+20AC (€) --> 0xE2 0x82 0xAC, 3 UTF-8 characters
        0xD55C, // U+D55C (한)--> 0xED 0x95 0x9C, 3 UTF-8 characters
        0xD801, 0xDC37, // U+10437 (𐐷) --> 0xF0 0x90 0x90 0xB7, 4 UTF-8 characters
    };

    char output[1 + 2 + 3 + 3 + 3 + 4 + 1];     // Room for null

    utf16_to_utf8(str, 7, output, sizeof(output));

    EXPECT_EQ('\x24', output[0]) << "should be 0x24";
    EXPECT_EQ('\xC2', output[1]) << "should be 0xC2";
    EXPECT_EQ('\xA3', output[2]) << "should be 0xA3";
    EXPECT_EQ('\xE0', output[3]) << "should be 0xE0";
    EXPECT_EQ('\xA4', output[4]) << "should be 0xA4";
    EXPECT_EQ('\xB9', output[5]) << "should be 0xB9";
    EXPECT_EQ('\xE2', output[6]) << "should be 0xE2";
    EXPECT_EQ('\x82', output[7]) << "should be 0x82";
    EXPECT_EQ('\xAC', output[8]) << "should be 0xAC";
    EXPECT_EQ('\xED', output[9]) << "should be 0xED";
    EXPECT_EQ('\x95', output[10]) << "should be 0x95";
    EXPECT_EQ('\x9C', output[11]) << "should be 0x9C";
    EXPECT_EQ('\xF0', output[12]) << "should be 0xF0";
    EXPECT_EQ('\x90', output[13]) << "should be 0x90";
    EXPECT_EQ('\x90', output[14]) << "should be 0x90";
    EXPECT_EQ('\xB7', output[15]) << "should be 0xB7";
    EXPECT_EQ('\x00', output[16]) << "should be 0x00";
}

TEST_F(UnicodeTest, strstr16EmptyTarget) {
    EXPECT_EQ(strstr16(kSearchString, u""), kSearchString)
            << "should return the original pointer";
}

TEST_F(UnicodeTest, strstr16EmptyTarget_bug) {
    // In the original code when target is an empty string strlen16() would
    // start reading the memory until a "terminating null" (that is, zero)
    // character is found.   This happens because "*target++" in the original
    // code would increment the pointer beyond the actual string.
    void* memptr;
    const size_t alignment = sysconf(_SC_PAGESIZE);
    const size_t size = 2 * alignment;
    ASSERT_EQ(posix_memalign(&memptr, alignment, size), 0);
    // Fill allocated memory.
    memset(memptr, 'A', size);
    // Create a pointer to an "empty" string on the first page.
    char16_t* const emptyString = (char16_t* const)((char*)memptr + alignment - 4);
    *emptyString = (char16_t)0;
    // Protect the second page to show that strstr16() violates that.
    ASSERT_EQ(mprotect((char*)memptr + alignment, alignment, PROT_NONE), 0);
    // Test strstr16(): when bug is present a segmentation fault is raised.
    ASSERT_EQ(strstr16((char16_t*)memptr, emptyString), (char16_t*)memptr)
        << "should not read beyond the first char16_t.";
    // Reset protection of the second page
    ASSERT_EQ(mprotect((char*)memptr + alignment, alignment, PROT_READ | PROT_WRITE), 0);
    // Free allocated memory.
    free(memptr);
}

TEST_F(UnicodeTest, strstr16SameString) {
    const char16_t* result = strstr16(kSearchString, kSearchString);
    EXPECT_EQ(kSearchString, result)
            << "should return the original pointer";
}

TEST_F(UnicodeTest, strstr16TargetStartOfString) {
    const char16_t* result = strstr16(kSearchString, u"I am");
    EXPECT_EQ(kSearchString, result)
            << "should return the original pointer";
}


TEST_F(UnicodeTest, strstr16TargetEndOfString) {
    const char16_t* result = strstr16(kSearchString, u"wind.");
    EXPECT_EQ(kSearchString+19, result);
}

TEST_F(UnicodeTest, strstr16TargetWithinString) {
    const char16_t* result = strstr16(kSearchString, u"leaf");
    EXPECT_EQ(kSearchString+7, result);
}

TEST_F(UnicodeTest, strstr16TargetNotPresent) {
    const char16_t* result = strstr16(kSearchString, u"soar");
    EXPECT_EQ(nullptr, result);
}

// http://b/29267949
// Test that overreading in utf8_to_utf16_length is detected
TEST_F(UnicodeTest, InvalidUtf8OverreadDetected) {
    // An utf8 char starting with \xc4 is two bytes long.
    // Add extra zeros so no extra memory is read in case the code doesn't
    // work as expected.
    static char utf8[] = "\xc4\x00\x00\x00";
    ASSERT_DEATH(utf8_to_utf16_length((uint8_t *) utf8, strlen(utf8),
            true /* overreadIsFatal */), "" /* regex for ASSERT_DEATH */);
}

}

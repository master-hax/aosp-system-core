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
#include <utils/Log.h>
#include <utils/Unicode.h>

#include <gtest/gtest.h>

namespace android {

class UnicodeTest : public testing::Test {
protected:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    }
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
        0x30, // U+0030, 1 UTF-16 character
        0xC4, 0x80, // U+0100, 1 UTF-16 character
        0xE2, 0x8C, 0xA3, // U+2323, 1 UTF-16 character
        0xF0, 0x90, 0x80, 0x80, // U+10000, 2 UTF-16 character
    };

    char16_t output[1 + 1 + 1 + 2 + 1]; // Room for NULL

    utf8_to_utf16(str, sizeof(str), output);

    EXPECT_EQ(0x0030, output[0])
            << "should be U+0030";
    EXPECT_EQ(0x0100, output[1])
            << "should be U+0100";
    EXPECT_EQ(0x2323, output[2])
            << "should be U+2323";
    EXPECT_EQ(0xD800, output[3])
            << "should be first half of surrogate U+10000";
    EXPECT_EQ(0xDC00, output[4])
            << "should be second half of surrogate U+10000";
    EXPECT_EQ(NULL, output[5])
            << "should be NULL terminated";
}

TEST_F(UnicodeTest, UTF16toUTF8Bounds) {
     uint16_t invalid[] = {
      0xd97f, 0x007a
    };
    const int len = 10;
    char output1[len];
    char output2[len];
    ssize_t outlen = 0;
    ssize_t measured = utf16_to_utf8_length(invalid, 2);

    if (measured >= 0) {
        memset(output1, 0x55, sizeof(output1));
        memset(output2, 0xAA, sizeof(output2));

        utf16_to_utf8(invalid, 2, output1);
        utf16_to_utf8(invalid, 2, output2);

        // output1 and output2 will be equal for all
        // positions utf16_to_utf8 has written to

        ssize_t written = 0;
        for (int i = 0; i < len; i++) {
            if (output1[i] == output2[i])
              written++;
        }

        EXPECT_EQ(measured+1, written)
                << "utf16_to_utf8 should write exactly measured+1 bytes";
    }
}

TEST_F(UnicodeTest, UTF16toUTF8InvalidSurrogate) {
     uint16_t invalid[] = {
      0xd97f, 0x007a
    };
    ssize_t measured = utf16_to_utf8_length(invalid, 2);
    EXPECT_EQ(-1, measured)
            << "Measured invalid UTF-16 should return -1";
}

}

/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <android-base/stringprintf.h>
#include <android-base/test_utils.h>
#include <gtest/gtest.h>

using namespace std::literals::string_literals;

namespace android {
namespace init {

TEST(util, ReadFile_ENOENT) {
    errno = 0;
    auto file_contents = ReadFile("/proc/does-not-exist");
    EXPECT_EQ(ENOENT, errno);
    ASSERT_FALSE(file_contents);
    EXPECT_EQ("open() failed: No such file or directory", file_contents.error_string());
}

TEST(util, ReadFileGroupWriteable) {
    std::string s("hello");
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    EXPECT_TRUE(WriteFile(tf.path, s)) << strerror(errno);
    EXPECT_NE(-1, fchmodat(AT_FDCWD, tf.path, 0620, AT_SYMLINK_NOFOLLOW)) << strerror(errno);
    auto file_contents = ReadFile(tf.path);
    ASSERT_FALSE(file_contents) << strerror(errno);
    EXPECT_EQ("Skipping insecure file", file_contents.error_string());
}

TEST(util, ReadFileWorldWiteable) {
    std::string s("hello");
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    EXPECT_TRUE(WriteFile(tf.path, s)) << strerror(errno);
    EXPECT_NE(-1, fchmodat(AT_FDCWD, tf.path, 0602, AT_SYMLINK_NOFOLLOW)) << strerror(errno);
    auto file_contents = ReadFile(tf.path);
    ASSERT_FALSE(file_contents) << strerror(errno);
    EXPECT_EQ("Skipping insecure file", file_contents.error_string());
}

TEST(util, ReadFileSymbolicLink) {
    errno = 0;
    // lrwxrwxrwx 1 root root 13 1970-01-01 00:00 charger -> /sbin/healthd
    auto file_contents = ReadFile("/charger");
    EXPECT_EQ(ELOOP, errno);
    ASSERT_FALSE(file_contents);
    EXPECT_EQ("open() failed: Too many symbolic links encountered", file_contents.error_string());
}

TEST(util, ReadFileSuccess) {
    auto file_contents = ReadFile("/proc/version");
    ASSERT_TRUE(file_contents);
    EXPECT_GT(file_contents->length(), 6U);
    EXPECT_EQ('\n', file_contents->at(file_contents->length() - 1));
    (*file_contents)[5] = 0;
    EXPECT_STREQ("Linux", file_contents->c_str());
}

TEST(util, WriteFileBinary) {
    std::string contents("abcd");
    contents.push_back('\0');
    contents.push_back('\0');
    contents.append("dcba");
    ASSERT_EQ(10u, contents.size());

    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    EXPECT_TRUE(WriteFile(tf.path, contents)) << strerror(errno);

    auto read_back_contents = ReadFile(tf.path);
    ASSERT_TRUE(read_back_contents) << strerror(errno);
    EXPECT_EQ(contents, *read_back_contents);
    EXPECT_EQ(10u, read_back_contents->size());
}

TEST(util, WriteFileNotExist) {
    std::string s("hello");
    TemporaryDir test_dir;
    std::string path = android::base::StringPrintf("%s/does-not-exist", test_dir.path);
    EXPECT_TRUE(WriteFile(path, s));
    auto file_contents = ReadFile(path);
    ASSERT_TRUE(file_contents);
    EXPECT_EQ(s, *file_contents);
    struct stat sb;
    int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    EXPECT_NE(-1, fd);
    EXPECT_EQ(0, fstat(fd, &sb));
    EXPECT_EQ((const unsigned int)(S_IRUSR | S_IWUSR), sb.st_mode & 0777);
    EXPECT_EQ(0, unlink(path.c_str()));
}

TEST(util, WriteFileExist) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    EXPECT_TRUE(WriteFile(tf.path, "1hello1")) << strerror(errno);
    auto file_contents = ReadFile(tf.path);
    ASSERT_TRUE(file_contents);
    EXPECT_EQ("1hello1", *file_contents);
    EXPECT_TRUE(WriteFile(tf.path, "2ll2"));
    file_contents = ReadFile(tf.path);
    ASSERT_TRUE(file_contents);
    EXPECT_EQ("2ll2", *file_contents);
}

TEST(util, DecodeUid) {
    auto decoded_uid = DecodeUid("root");
    EXPECT_TRUE(decoded_uid);
    EXPECT_EQ(0U, *decoded_uid);

    decoded_uid = DecodeUid("toot");
    EXPECT_FALSE(decoded_uid);
    EXPECT_EQ("getpwnam failed: No such file or directory", decoded_uid.error_string());

    decoded_uid = DecodeUid("123");
    EXPECT_TRUE(decoded_uid);
    EXPECT_EQ(123U, *decoded_uid);
}

TEST(util, is_dir) {
    TemporaryDir test_dir;
    EXPECT_TRUE(is_dir(test_dir.path));
    TemporaryFile tf;
    EXPECT_FALSE(is_dir(tf.path));
}

TEST(util, mkdir_recursive) {
    TemporaryDir test_dir;
    std::string path = android::base::StringPrintf("%s/three/directories/deep", test_dir.path);
    EXPECT_TRUE(mkdir_recursive(path, 0755));
    std::string path1 = android::base::StringPrintf("%s/three", test_dir.path);
    EXPECT_TRUE(is_dir(path1.c_str()));
    std::string path2 = android::base::StringPrintf("%s/three/directories", test_dir.path);
    EXPECT_TRUE(is_dir(path1.c_str()));
    std::string path3 = android::base::StringPrintf("%s/three/directories/deep", test_dir.path);
    EXPECT_TRUE(is_dir(path1.c_str()));
}

TEST(util, mkdir_recursive_extra_slashes) {
    TemporaryDir test_dir;
    std::string path = android::base::StringPrintf("%s/three////directories/deep//", test_dir.path);
    EXPECT_TRUE(mkdir_recursive(path, 0755));
    std::string path1 = android::base::StringPrintf("%s/three", test_dir.path);
    EXPECT_TRUE(is_dir(path1.c_str()));
    std::string path2 = android::base::StringPrintf("%s/three/directories", test_dir.path);
    EXPECT_TRUE(is_dir(path1.c_str()));
    std::string path3 = android::base::StringPrintf("%s/three/directories/deep", test_dir.path);
    EXPECT_TRUE(is_dir(path1.c_str()));
}

TEST(util, Serialization) {
    auto serializer = Serializer();
    std::string hand_generated_contents;

    serializer.WriteUint32(0x235C41F8);
    hand_generated_contents += "\xF8\x41\x5C\x23"s;

    serializer.WriteString("test string"s);
    hand_generated_contents += "\x0B\x00\x00\x00"s;
    hand_generated_contents += "test string";

    serializer.WriteString("\x00\x01\x02\xFF\xFE\xFD\x7F\x8F\x9F"s);
    hand_generated_contents += "\x09\x00\x00\x00"s;
    hand_generated_contents += "\x00\x01\x02\xFF\xFE\xFD\x7F\x8F\x9F"s;

    serializer.WriteString("");
    hand_generated_contents += "\x00\x00\x00\x00"s;

    serializer.WriteStrings(std::vector<std::string>{"these", "are", "strings"});
    hand_generated_contents += "\x03\x00\x00\x00"s;
    hand_generated_contents += "\x05\x00\x00\x00"s;
    hand_generated_contents += "these";
    hand_generated_contents += "\x03\x00\x00\x00"s;
    hand_generated_contents += "are";
    hand_generated_contents += "\x07\x00\x00\x00"s;
    hand_generated_contents += "strings";

    EXPECT_EQ(hand_generated_contents, serializer.contents());
}

TEST(util, Deserialization) {
    std::string hand_generated_contents;

    uint32_t int_value = 0x235C41F8;
    hand_generated_contents += "\xF8\x41\x5C\x23"s;

    auto test_string = "test string"s;
    hand_generated_contents += "\x0B\x00\x00\x00"s;
    hand_generated_contents += "test string";

    auto hex_string_with_null = "\x00\x01\x02\xFF\xFE\xFD\x7F\x8F\x9F"s;
    hand_generated_contents += "\x09\x00\x00\x00"s;
    hand_generated_contents += "\x00\x01\x02\xFF\xFE\xFD\x7F\x8F\x9F"s;

    auto empty_string = std::string();
    hand_generated_contents += "\x00\x00\x00\x00"s;

    auto strings = std::vector<std::string>{"these", "are", "strings"};
    hand_generated_contents += "\x03\x00\x00\x00"s;
    hand_generated_contents += "\x05\x00\x00\x00"s;
    hand_generated_contents += "these";
    hand_generated_contents += "\x03\x00\x00\x00"s;
    hand_generated_contents += "are";
    hand_generated_contents += "\x07\x00\x00\x00"s;
    hand_generated_contents += "strings";

    auto deserializer = Deserializer(hand_generated_contents);

    auto checker = [&deserializer](auto expected, auto read_function) {
        auto result = std::invoke(read_function, deserializer);
        ASSERT_TRUE(result);
        EXPECT_EQ(expected, *result);
    };

    checker(int_value, &Deserializer::ReadUint32);
    checker(test_string, &Deserializer::ReadString);
    checker(hex_string_with_null, &Deserializer::ReadString);
    checker(empty_string, &Deserializer::ReadString);
    checker(strings, &Deserializer::ReadStrings);
}

TEST(util, SerializationDeserialization) {
    auto command1 = std::vector<std::string>{"mkdir", "/dev/something"};
    auto command2 = std::vector<std::string>{"write", "/dev/something", "/something_else"};
    auto command3 = std::vector<std::string>{"other command", "do something\"quoted\""};
    auto result = "this failed"s;
    uint32_t result_errno = 6;

    auto serializer = Serializer();
    serializer.WriteStrings(command1);
    serializer.WriteStrings(command2);
    serializer.WriteStrings(command3);
    serializer.WriteString(result);
    serializer.WriteUint32(result_errno);

    auto deserializer = Deserializer(serializer.contents());

    auto checker = [&deserializer](auto expected, auto read_function) {
        auto result = std::invoke(read_function, deserializer);
        ASSERT_TRUE(result);
        EXPECT_EQ(expected, *result);
    };

    checker(command1, &Deserializer::ReadStrings);
    checker(command2, &Deserializer::ReadStrings);
    checker(command3, &Deserializer::ReadStrings);
    checker(result, &Deserializer::ReadString);
    checker(result_errno, &Deserializer::ReadUint32);
}

}  // namespace init
}  // namespace android

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

#include "property_service.h"

#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

#include <android-base/test_utils.h>
#include <gtest/gtest.h>

#include "util.h"

using namespace std::string_literals;

namespace android {
namespace init {

TEST(property_service, very_long_name_35166374) {
  // Connect to the property service directly...
  int fd = socket(AF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
  ASSERT_NE(fd, -1);

  static const char* property_service_socket = "/dev/socket/" PROP_SERVICE_NAME;
  sockaddr_un addr = {};
  addr.sun_family = AF_LOCAL;
  strlcpy(addr.sun_path, property_service_socket, sizeof(addr.sun_path));

  socklen_t addr_len = strlen(property_service_socket) + offsetof(sockaddr_un, sun_path) + 1;
  ASSERT_NE(connect(fd, reinterpret_cast<sockaddr*>(&addr), addr_len), -1);

  // ...so we can send it a malformed request.
  uint32_t msg = PROP_MSG_SETPROP2;
  uint32_t size = 0xffffffff;
  uint32_t data = 0xdeadbeef;

  ASSERT_EQ(static_cast<ssize_t>(sizeof(msg)), send(fd, &msg, sizeof(msg), 0));
  ASSERT_EQ(static_cast<ssize_t>(sizeof(size)), send(fd, &size, sizeof(size), 0));
  ASSERT_EQ(static_cast<ssize_t>(sizeof(data)), send(fd, &data, sizeof(data), 0));
  ASSERT_EQ(0, close(fd));
}

TEST(property_service, PersistentPropertyFile_EndToEnd) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::vector<std::pair<std::string, std::string>> persistent_properties = {
        {"persist.sys.locale", "en-US"},
        {"persist.sys.timezone", "America/Los_Angeles"},
        {"persist.test.empty.value", ""},
        {"persist.test.new.line", "abc\n\n\nabc"},
        {"persist.test.numbers", "1234567890"},
        {"persist.test.non.ascii", "\x00\x01\x02\xFF\xFE\xFD\x7F\x8F\x9F"},
        // We don't currently allow for non-ascii keys for system properties, but this is a policy
        // decision, not a technical limitation.
        {"persist.\x00\x01\x02\xFF\xFE\xFD\x7F\x8F\x9F", "non-ascii-key"},
    };
    auto persistent_property_file = PersistentPropertyFile(tf.path);
    persistent_property_file.Write(persistent_properties);
    auto read_back_properties = persistent_property_file.Load();
    ASSERT_TRUE(read_back_properties) << read_back_properties.error();
    EXPECT_EQ(persistent_properties, *read_back_properties);
}

TEST(property_service, PersistentPropertyFile) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);

    const std::vector<std::pair<std::string, std::string>> persistent_properties = {
        {"persist.abc", ""}, {"persist.def", "test_success"},
    };

    // Manually serialized contents below:
    std::string file_contents;
    // All values below are written and read as little endian.
    // Add magic value: 0x8495E0B4
    file_contents += "\xB4\xE0\x95\x84"s;
    // Add version: 1
    file_contents += "\x01\x00\x00\x00"s;
    // Add number of properties: 2
    file_contents += "\x02\x00\x00\x00"s;

    // Add first key: persist.abc
    file_contents += "\x0B\x00\x00\x00persist.abc"s;
    // Add first value: (empty string)
    file_contents += "\x00\x00\x00\x00"s;

    // Add second key: persist.def
    file_contents += "\x0B\x00\x00\x00persist.def"s;
    // Add second value: test_success
    file_contents += "\x0C\x00\x00\x00test_success"s;

    ASSERT_TRUE(WriteFile(tf.path, file_contents));

    auto persistent_property_file = PersistentPropertyFile(tf.path);
    auto read_back_properties = persistent_property_file.Load();
    ASSERT_TRUE(read_back_properties) << read_back_properties.error();

    EXPECT_EQ(persistent_properties, *read_back_properties);
}

TEST(property_service, PersistentPropertyFile_BadMagic) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);

    ASSERT_TRUE(WriteFile(tf.path, "ab"));

    auto persistent_property_file = PersistentPropertyFile(tf.path);
    auto read_back_properties = persistent_property_file.Load();

    ASSERT_FALSE(read_back_properties);
    EXPECT_EQ("Could not read magic value: Input buffer not large enough to read uint32_t",
              read_back_properties.error_string());

    ASSERT_TRUE(WriteFile(tf.path, "\xFF\xFF\xFF\xFF"));

    read_back_properties = persistent_property_file.Load();

    ASSERT_FALSE(read_back_properties);
    EXPECT_EQ("Magic value '0xffffffff' does not match expected value '0x8495e0b4'",
              read_back_properties.error_string());
}

}  // namespace init
}  // namespace android

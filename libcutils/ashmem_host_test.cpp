/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <unistd.h>

#include <android-base/unique_fd.h>
#include <cutils/ashmem.h>

#ifdef _WIN32
#include <windows.h>
#endif
using android::base::unique_fd;

/*
 * This is a test for ashmem simulation on host platforms. Because ashmem
 * support on host is limited, this test is more minimal.
 */
TEST(AshmemHostTest, TestCreate) {
#ifdef _WIN32
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    int size = systemInfo.dwPageSize;
#else
    int size = getpagesize();
#endif

    uint8_t data[size];
    std::memset(data, 0xff, size);
    unique_fd fd;
    fd = unique_fd(ashmem_create_region(nullptr, size));
    ASSERT_TRUE(fd >= 0);
    ASSERT_TRUE(ashmem_valid(fd));
    ASSERT_EQ(size, ashmem_get_size_region(fd));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

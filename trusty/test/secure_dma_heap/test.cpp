/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <BufferAllocator/BufferAllocator.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <string.h>
#include <trusty/tipc.h>

using ::android::base::unique_fd;

namespace android {
namespace trusty {

class SecureDmaHeapTest : public ::testing::Test {
  public:
    unique_fd AllocSecureBuf(size_t len) {
        return unique_fd(allocator_.Alloc("vframe-secure", len));
    }

    BufferAllocator allocator_;
};

TEST_F(SecureDmaHeapTest, AllocOnePage) {
    unique_fd buf = AllocSecureBuf(PAGE_SIZE);
    ASSERT_GE(buf, 0);
}

TEST_F(SecureDmaHeapTest, FailAlloc) {
    unique_fd buf0 = AllocSecureBuf(PAGE_SIZE * 20000);
    EXPECT_GE(buf0, 0);

    unique_fd buf1 = AllocSecureBuf(PAGE_SIZE);
    EXPECT_GE(buf1, 0);
}

TEST_F(SecureDmaHeapTest, CrashHypervisor) {
    unique_fd buf0 = AllocSecureBuf(PAGE_SIZE * 1000);
    unique_fd buf1 = AllocSecureBuf(PAGE_SIZE * 100000);
    unique_fd buf2 = AllocSecureBuf(PAGE_SIZE * 1000);
}

}  // namespace trusty
}  // namespace android

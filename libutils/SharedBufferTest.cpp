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

#include <utils/SharedBuffer.h>

#include <gtest/gtest.h>

#include <memory>
#include <stdint.h>

TEST(SharedBufferTest, TestAlloc) {
  EXPECT_DEATH(android::SharedBuffer::alloc(SIZE_MAX), "");
  EXPECT_DEATH(android::SharedBuffer::alloc(SIZE_MAX - sizeof(android::SharedBuffer)), "");

  // Make sure we don't die here. Returning null is accepatable, since there
  // might not be enough memory available to satisfy this request.
  android::SharedBuffer* buf =
      android::SharedBuffer::alloc(SIZE_MAX - sizeof(android::SharedBuffer) - 1);
  if (buf != nullptr) {
     buf->release();
  }

  buf = android::SharedBuffer::alloc(0);
  ASSERT_NE(nullptr, buf);
  ASSERT_EQ(0U, buf->size());
  buf->release();
}

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

#include "shmem.h"

#include <android-base/result-gmock.h>
#include <gtest/gtest.h>

#define ASSERT_RESULT_NOT_OK(e) ASSERT_THAT(e, Not(Ok()))

using ::android::base::Result;
using ::android::base::testing::Ok;
using ::testing::Not;

namespace android {
namespace init {

TEST(SharedMemory, SharedMemory) {
    SharedMemory shm(4096);
    ASSERT_RESULT_OK(shm.CreateMemfd());
    ASSERT_RESULT_NOT_OK(shm.CreateMemfd());
    ASSERT_RESULT_OK(shm.Map());
    ASSERT_RESULT_NOT_OK(shm.Map());
    ASSERT_RESULT_OK(shm.Unmap());
    ASSERT_RESULT_OK(shm.Unmap());
}

}  // namespace init
}  // namespace android

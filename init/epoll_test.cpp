/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "epoll.h"

#include <sys/unistd.h>

#include <unordered_set>

#include <android-base/file.h>
#include <gtest/gtest.h>

namespace android {
namespace init {

TEST(epoll, UnregisterHandler) {
    Epoll epoll;
    ASSERT_RESULT_OK(epoll.Open());

    int fds[2];
    ASSERT_EQ(pipe(fds), 0);

    bool handler_invoked;
    auto handler = [&]() -> void {
        auto result = epoll.UnregisterHandler(fds[0]);
        ASSERT_EQ(result.ok(), !handler_invoked);
        handler_invoked = true;
    };

    epoll.RegisterHandler(fds[0], handler);

    uint8_t byte = 0xee;
    ASSERT_TRUE(android::base::WriteFully(fds[1], &byte, sizeof(byte)));

    auto epoll_result = epoll.Wait({});
    ASSERT_RESULT_OK(epoll_result);
    ASSERT_EQ(*epoll_result, 1);
    ASSERT_TRUE(handler_invoked);
}

}  // namespace init
}  // namespace android

/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "adb_listeners.h"

#include <gtest/gtest.h>

#include <android-base/stringprintf.h>

#include "sysdeps.h"

using namespace internal;

// Tests local_name_to_fd() with TCP port 0.
TEST(adb_listeners_test, test_local_name_to_fd_tcp_port_0) {
    alistener listener("tcp:0", "tcp:8000");
    int resolved_tcp_port = 0;
    std::string error;

    int sock = local_name_to_fd(&listener, &resolved_tcp_port, &error);
    ASSERT_GE(sock, 0);
    ASSERT_GT(resolved_tcp_port, 0);
    ASSERT_EQ(android::base::StringPrintf("tcp:%d", resolved_tcp_port), listener.local_name);
    ASSERT_EQ(0, adb_close(sock));
}

/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "NativeBridgeTest.h"

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

namespace android {

// Tests that the bridge is initialized without errors if the code_cache is NULL.
TEST_F(NativeBridgeTest, CodeCacheNull) {
    // Make sure that code_cache does not exists
    struct stat st;
    ASSERT_EQ(-1, stat(kCodeCache, &st));
    ASSERT_EQ(ENOENT, errno);

    // Load library
    ASSERT_TRUE(LoadNativeBridge(kNativeBridgeLibrary, nullptr));
    // Pass nullptr as code_cache
    ASSERT_TRUE(PreInitializeNativeBridge(nullptr, "isa"));
    // Init
    ASSERT_TRUE(InitializeNativeBridge(nullptr, nullptr));
    ASSERT_TRUE(NativeBridgeAvailable());
    ASSERT_FALSE(NativeBridgeError());

    // Clean up
    UnloadNativeBridge();

    ASSERT_FALSE(NativeBridgeError());
}

}  // namespace android

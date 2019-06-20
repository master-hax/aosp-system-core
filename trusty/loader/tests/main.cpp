/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <assert.h>
#include <gtest/gtest.h>
#include <stdint.h>
#include <trusty/lib/loader.h>
#include <trusty/tipc.h>

#define TRUSTY_DEVICE_NAME "/dev/trusty-ipc-dev0"
#define LOADABLE_APP_NAME "test-app.elf"
#define LOADABLE_APP_UUID "4b49d683-2a79-4015-a1d8-ab7c8c99d94f"
#define LOADABLE_APP_PORT "com.android.trusty.loader.test"
#define SELF_NAME "trusty-loader-test"

static int wait_for_unload(const char* app_uuid) {
    int rc;

    rc = loader_unload(TRUSTY_DEVICE_NAME, app_uuid);
    while (rc == ERR_APP_RUNNING) {
        sleep(1);
        rc = loader_unload(TRUSTY_DEVICE_NAME, app_uuid);
    }

    return rc;
}

// TODO: Add tests for the underlying layers and sending invalid requests
TEST(LoaderServiceTest, LoadUnload) {
    int rc;

    rc = loader_load(TRUSTY_DEVICE_NAME, LOADABLE_APP_NAME);
    ASSERT_EQ(NO_ERROR, rc) << loader_error_to_str(rc);

    rc = loader_unload(TRUSTY_DEVICE_NAME, LOADABLE_APP_UUID);
    ASSERT_EQ(NO_ERROR, rc) << loader_error_to_str(rc);
}

TEST(LoaderServiceTest, LoadInvalid) {
    int rc;

    rc = loader_load(TRUSTY_DEVICE_NAME ".invalid", LOADABLE_APP_NAME);
    EXPECT_EQ(ERR_TIPC, rc) << loader_error_to_str(rc);

    rc = loader_load(TRUSTY_DEVICE_NAME, LOADABLE_APP_NAME ".invalid");
    EXPECT_EQ(ERR_INPUT, rc) << loader_error_to_str(rc);

    /* Loading a non-Trusty app (this test's executable) should fail*/
    rc = loader_load(TRUSTY_DEVICE_NAME, SELF_NAME);
    EXPECT_EQ(ERR_INVALID_ARGS, rc) << loader_error_to_str(rc);

    /* Load the app */
    rc = loader_load(TRUSTY_DEVICE_NAME, LOADABLE_APP_NAME);
    ASSERT_EQ(NO_ERROR, rc) << loader_error_to_str(rc);

    /* Loading an app with the same UUID should fail */
    rc = loader_load(TRUSTY_DEVICE_NAME, LOADABLE_APP_NAME);
    EXPECT_EQ(ERR_APP_EXISTS, rc) << loader_error_to_str(rc);

    /* Clean up */
    rc = loader_unload(TRUSTY_DEVICE_NAME, LOADABLE_APP_UUID);
    EXPECT_EQ(NO_ERROR, rc) << loader_error_to_str(rc);
}

TEST(LoaderServiceTest, UnloadInvalid) {
    int rc;
    int tipc_fd;

    rc = loader_unload(TRUSTY_DEVICE_NAME ".invalid", LOADABLE_APP_UUID);
    EXPECT_EQ(ERR_TIPC, rc) << loader_error_to_str(rc);

    rc = loader_unload(TRUSTY_DEVICE_NAME, "not a uuid");
    EXPECT_EQ(ERR_INVALID_ARGS, rc) << loader_error_to_str(rc);

    rc = loader_unload(TRUSTY_DEVICE_NAME, LOADABLE_APP_UUID);
    EXPECT_EQ(ERR_APP_NOT_FOUND, rc) << loader_error_to_str(rc);

    /* Load the app */
    rc = loader_load(TRUSTY_DEVICE_NAME, LOADABLE_APP_NAME);
    ASSERT_EQ(NO_ERROR, rc) << loader_error_to_str(rc);

    /* Start the application */
    rc = tipc_connect(TRUSTY_DEVICE_NAME, LOADABLE_APP_PORT);
    ASSERT_GE(rc, 0);

    tipc_fd = rc;

    /* Unloading a running application should fail */
    rc = loader_unload(TRUSTY_DEVICE_NAME, LOADABLE_APP_UUID);
    EXPECT_EQ(ERR_APP_RUNNING, rc) << loader_error_to_str(rc);

    /* Shutdown the application */
    tipc_close(tipc_fd);

    /* Clean up */
    rc = wait_for_unload(LOADABLE_APP_UUID);
    EXPECT_EQ(NO_ERROR, rc) << loader_error_to_str(rc);
}

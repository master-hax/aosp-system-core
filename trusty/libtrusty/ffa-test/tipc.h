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

#pragma once

#include <stdint.h>

/* TIPC interface definition */
#define FFA_TEST_SRV_PORT "com.android.trusty.ffa.test.srv"

enum ffa_test_srv_cmd {
    FFA_TEST_SRV_CMD_MAP_WRITE_UNMAP = 1,
    FFA_TEST_SRV_CMD_MAP_WRITE = 2,
};

struct ffa_test_srv_req {
    uint32_t cmd;
    uint32_t size;
    uint32_t arg;
};

struct ffa_test_srv_resp {
    uint32_t cmd;
};

#define MAX_MAPPED_BUFS 10
#define MAX_MSG_SIZE (MAX(sizeof(struct ffa_test_srv_req), sizeof(struct ffa_test_srv_resp)))

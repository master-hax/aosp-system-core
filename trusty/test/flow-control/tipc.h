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

#pragma once

#include <sys/types.h>

#define FLOW_CONTROL_TEST_SRV_PORT "com.android.trusty.flow-control-test.srv"

#define FLOW_CONTROL_TEST_SRV_STOP_BIT (1u)
#define FLOW_CONTROL_TEST_SRV_REQ_SHIFT (1u)

enum flow_control_test_srv_cmd {
    FLOW_CONTROL_TEST_SRV_MSG = (1u << FLOW_CONTROL_TEST_SRV_REQ_SHIFT),
};

struct flow_control_test_srv_hdr {
    uint32_t cmd;
    uint32_t frag_len;
    uint8_t frag[0];
};

#define FLOW_CONTROL_TEST_SRV_MSG_MAX_SIZE (8192)
#define FLOW_CONTROL_TEST_SRV_FRAG_MAX_SIZE (64)
#define FLOW_CONTROL_TEST_SRV_MSG_QUEUE_LEN (2)

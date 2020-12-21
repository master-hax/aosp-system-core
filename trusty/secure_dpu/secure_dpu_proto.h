/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <stdint.h>

/**
 * enum secure_dpu_cmd - command identifiers for secure_fb interface
 * @SECURE_DPU_CMD_RESP_BIT:
 *      Message is a response.
 * @SECURE_DPU_CMD_REQ_SHIFT:
 *      Number of bits used by @SECURE_DPU_CMD_RESP_BIT.
 * @SECURE_DPU_CMD_SET_BUFFER:
 *      Set up the buffer to be used for framebuffer
 */
enum secure_dpu_cmd {
    SECURE_DPU_CMD_RESP_BIT = 1,
    SECURE_DPU_CMD_REQ_SHIFT = 1,
    SECURE_DPU_CMD_ALLOCATE_BUFFER = (1 << SECURE_DPU_CMD_REQ_SHIFT),
    SECURE_DPU_CMD_FREE_BUFFER = (2 << SECURE_DPU_CMD_REQ_SHIFT),
    SECURE_DPU_CMD_START_SECURE_DISPLAY = (3 << SECURE_DPU_CMD_REQ_SHIFT),
    SECURE_DPU_CMD_STOP_SECURE_DISPLAY = (4 << SECURE_DPU_CMD_REQ_SHIFT),
};

/**
 * struct secure_dpu_allocate_buffer_req - payload for
 *                                         %SECURE_DPU_CMD_ALLOCATE_BUFFER
 * request
 * @buffer_phy_addr: Physical address of the buffer
 * @buffer_len: Requested length
 */
struct secure_dpu_allocate_buffer_req {
    uint64_t buffer_len;
};

/**
 * struct secure_dpu_allocate_buffer_rsp - response for
 *                                         %SECURE_DPU_CMD_ALLOCATE_BUFFER
 * request
 * @buffer_phy_addr: Physical address of the buffer
 * @buffer_len: Length of the allocated buffer
 */
struct secure_dpu_allocate_buffer_rsp {
    uint64_t buffer_phy_addr;
    uint64_t buffer_len;
};

/**
 * struct secure_dpu_free_buffer_req - payload for
 *                                     %SECURE_DPU_CMD_FREE_BUFFER
 * request
 * @buffer_phy_addr: Physical address of the buffer
 * @buffer_len: Length of the buffer
 */
struct secure_dpu_free_buffer_req {
    uint64_t buffer_phy_addr;
    uint64_t buffer_len;
};

/**
 * struct secure_fb_req - common structure for secure_fb requests.
 * @cmd: Command identifier - one of &enum secure_dpu_cmd.
 */
struct secure_dpu_req {
    uint32_t cmd;
};

/**
 * struct secure_dpu_resp - common structure for secure_fb responses.
 * @cmd:    Command identifier - %SECURE_DPU_CMD_RESP_BIT or'ed with the
 *                               command identifier of the corresponding
 * request.
 * @status: Status of requested operation. One of &enum secure_dpu_error.
 */
struct secure_dpu_resp {
    uint32_t cmd;
    uint32_t status;
};

enum secure_dpu_error {
    SECURE_DPU_ERROR_OK = 0,
    SECURE_DPU_ERROR_FAIL = -1,
    SECURE_DPU_ERROR_UNINITIALIZED = -2,
    SECURE_DPU_ERROR_PARAMETERS = -3,
    SECURE_DPU_ERROR_NO_MEMORY = -3,
};

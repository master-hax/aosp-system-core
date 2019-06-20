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

#pragma once

#include <stdint.h>

#define LOADER_PORT "com.android.trusty.loader"
#define LOADER_UUID_STR_SIZE (37)

enum loader_cmd {
    LOADER_CMD_LOAD,
    LOADER_CMD_UNLOAD,
};

enum loader_err {
    LOADER_NO_ERROR,
    LOADER_ERR_INTERNAL,
    LOADER_ERR_INVALID_REQ,
    LOADER_ERR_INVALID_CMD,
    LOADER_ERR_INVALID_DATA,
    LOADER_ERR_ALREADY_EXISTS,
    LOADER_ERR_NOT_FOUND,
    LOADER_ERR_BUSY,
    LOADER_ERR_TIMED_OUT,
};

struct loader_req {
    enum loader_cmd cmd;
    uint32_t payload_size;
    uint8_t payload[];
};

struct loader_rsp {
    enum loader_err err;
};

struct load_cmd_data {
    uint8_t app_bin[0];
};

struct unload_cmd_data {
    char uuid_str[LOADER_UUID_STR_SIZE];
};

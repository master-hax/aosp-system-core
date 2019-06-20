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

#define LOADER_PORT "com.android.trusty.loader"
#define LOADER_UUID_STR_SIZE (37)

#include <stdint.h>

/**
 * enum loader_cmd - Commands for the loader protocol
 * @LOADER_CMD_LOAD:    Add a Trusty application into the system. This command
 *                      expects an application binary as an argument.
 * @LOADER_CMD_UNLOAD:  Remove a Trusty application from the system. This
 *                      command expects an application UUID as an argument.
 */
enum loader_cmd {
    LOADER_CMD_LOAD = 0,
    LOADER_CMD_UNLOAD = 1,
};

/**
 * enum loader_err - Error codes for the loader protocol
 * @LOADER_ERR_NO_ERROR:        No error.
 * @LOADER_ERR_INVALID_CMD:     The receive command is not one of
 *                              &enum loader_cmd.
 * @LOADER_ERR_INVALID_REQ_LEN: The receive request is too small or too big.
 * @LOADER_ERR_INVALID_DATA:    The data provided for the command (e.g. UUID or
 *                              application image) is not valid.
 * @LOADER_ERR_ALREADY_EXISTS:  The application trying to be loaded is already
 *                              in the system.
 * @LOADER_ERR_NOT_FOUND:       The application trying to be unloaded is not
 *                              part of the system.
 * @LOADER_ERR_BUSY:            The application trying to be unloaded is
 *                              currently running.
 * @LOADER_ERR_INTERNAL:        An internal server error occurred (e.g. OOM)
 */
enum loader_err {
    LOADER_NO_ERROR = 0,
    LOADER_ERR_INVALID_CMD = 1,
    LOADER_ERR_INVALID_REQ_LEN = 2,
    LOADER_ERR_INVALID_DATA = 3,
    LOADER_ERR_ALREADY_EXISTS = 4,
    LOADER_ERR_NOT_FOUND = 5,
    LOADER_ERR_BUSY = 6,
    LOADER_ERR_INTERNAL = 7,
};

/**
 * struct loader_req - Request format for loader commnads
 * @cmd:            one of &enum loader_cmd
 * @payload_size:   Size of the payload
 * @payload:        Payload containing command specific data
 */
struct loader_req {
    enum loader_cmd cmd;
    uint32_t payload_size;
    uint8_t payload[];
};

/**
 * struct loader_rsp - Response format for loader commnads
 * @err:            one of &enum loader_err
 */
struct loader_rsp {
    enum loader_err err;
};

/**
 * struct load_cmd_data - Format for the payload of a LOADER_LOAD_CMD Request
 * @app_bin: The application image to be loaded
 */
struct load_cmd_data {
    uint8_t app_bin[0];
};

/**
 * struct unload_cmd_data - Format for the payload of a LOADER_UNLOAD_CMD
 *                          Request
 * @uuid_str:   UUID of the application to be unloaded
 */
struct unload_cmd_data {
    char uuid_str[LOADER_UUID_STR_SIZE];
};

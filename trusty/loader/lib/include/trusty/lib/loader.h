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

#define TIPC_HEADER_SIZE (16)
#define MAX_TIPC_PAYLOAD_SIZE (PAGE_SIZE - TIPC_HEADER_SIZE)

__BEGIN_DECLS

/**
 * enum loader_error - Error codes for the loader library
 * @NO_ERROR:           No error.
 * @ERR_INPUT:          An error occurred when trying to read the input data
 * @ERR_TIPC:           An error occured during tipc operations (e.g. connect,
 *                      send, receive).
 * @ERR_SERVER:         The server returned an internal error.
 * @ERR_INVALID_ARGS:   The argumens provided are not valid.
 * @ERR_APP_NOT_FOUND:  The given application to be unloaded does not exist
 * @ERR_APP_RUNNING:    The given application to be loaded is already loaded
 * @ERR_NO_MEM:         The library failed to allocate memory.
 * @ERR_INVALID_RSP:    The server returned an invalid response.
 * @ERR_INTERNAL:       An internal library error ocurred.
 *
 */
enum loader_error {
    NO_ERROR = 0,
    ERR_INPUT = -1,
    ERR_TIPC = -2,
    ERR_SERVER = -3,
    ERR_INVALID_ARGS = -4,
    ERR_APP_NOT_FOUND = -5,
    ERR_APP_EXISTS = -6,
    ERR_APP_RUNNING = -7,
    ERR_NO_MEM = -8,
    ERR_INVALID_RSP = -9,
    ERR_INTERNAL = -10,
};

/**
 * loader_load() - Load a Trusty application
 * @dev_name:   device node to use for communicating with Trusty
 * @file_name:  file path to the Trusty application to load
 *
 * Return: one of &enum loader_error
 */
int loader_load(const char* dev_name, const char* file_name);

/**
 * loader_unload() - Unload a Trusty application
 * @dev_name:  device node to use for communicating with Trusty
 * @uuid_ste:  UUID string of the application to unload
 *
 * Return: one of &enum loader_error
 */
int loader_unload(const char* dev_name, const char* uuid_str);

/**
 * loader_error_to_str() - Convert a loader error into its string representation
 * @rsp: loader error to convert
 *
 * Return: A string representation of @rsp
 */
const char* loader_error_to_str(int rsp);

__END_DECLS

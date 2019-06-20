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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * enum trusty_loader_err - Error codes for the Trusty loader client library
 * @TRUSTY_LOADER_NO_ERROR: No error.
 * @TRUSTY_LOADER_ERR_IPC:  An error occured during ipc (e.g. send, receive).
 * @TRUSTY_LOADER_ERR_INVALID_RSP:  The server returned an invalid response.
 * @TRUSTY_LOADER_ERR_INVALID_ARGS: The arguments provided are invalid.
 */
enum trusty_loader_err {
    TRUSTY_LOADER_NO_ERROR,
    TRUSTY_LOADER_ERR_IPC,
    TRUSTY_LOADER_ERR_INVALID_RSP,
    TRUSTY_LOADER_ERR_INVALID_ARGS,
};

struct ipc_obj;
/**
 * typedef ipc_get_max_msg_size_func - Function to retreive the maximum amount
 *                                     of data that can be sent/received as a
 *                                     single message using an &struct ipc_obj
 * @obj: owner &struct ipc_obj object
 *
 * Return: The maximum message size supported by @obj
 */
typedef int (*ipc_get_max_msg_size_func_t)(struct ipc_obj* obj);

/**
 * typedef ipc_send_func_t - Function to send data to Trusty
 * @obj:    owner &struct ipc_obj object
 * @data:   data to send
 * @size:   size of @data
 *
 * Return: The number of bytes sent
 */
typedef int (*ipc_send_func_t)(struct ipc_obj* obj, const void* data, int size);

/**
 * typedef ipc_recv_func_t - Function to receive data from Trusty
 * @obj:    owner &struct ipc_obj object
 * @data:   buffer to receive data into
 * @size:   size of @data
 *
 * Return: The number of bytes received
 */
typedef int (*ipc_recv_func_t)(struct ipc_obj* obj, void* data, int size);

/**
 * struct ipc_obj - Object providing IPC functionality to communicate with
 *                  Trusty
 * @get_max_msg_size: Function to get the max size of an IPC message
 * @send:             Function to send an IPC message
 * @recv:             Function to receive an IPC message
 */
struct ipc_obj {
    ipc_get_max_msg_size_func_t get_max_msg_size;
    ipc_send_func_t send;
    ipc_recv_func_t recv;
};

/**
 * trusty_loader_load() - Load a Trusty application
 * @obj:        IPC object to use for communicating with Trusty
 * @app_data:   Buffer containing the application image
 * @app_size:   Size of @app_data
 * @rsp:        Out parameter to return the response from the loader server
 *
 * Return: one of &enum trusty_loader_err
 */
int trusty_loader_load(struct ipc_obj* obj, const void* app_data, int app_size, int* rsp);

/**
 * trusty_loader_unload() - Unload a Trusty application
 * @obj:        IPC object to use for communicating with Trusty
 * @app_uuid:   UUID string of the app to unload
 * @rsp:        Out parameter to return the response from the loader server
 *
 * Return: one of &enum trusty_loader_err
 */
int trusty_loader_unload(struct ipc_obj* obj, const char* app_uuid, int* rsp);

#ifdef __cplusplus
}
#endif

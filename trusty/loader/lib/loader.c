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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include <trusty/interface/loader.h>
#include <trusty/lib/loader.h>
#include <trusty/tipc.h>
#include "trusty_loader_client.h"

#define containerof(ptr, type, member) ((type*)((uintptr_t)(ptr)-offsetof(type, member)))

static int rsp_to_loader_err(int rsp) {
    switch (rsp) {
        case LOADER_NO_ERROR:
            return NO_ERROR;
        case LOADER_ERR_INVALID_CMD:
            return ERR_INTERNAL;
        case LOADER_ERR_INVALID_REQ_LEN:
            return ERR_INVALID_ARGS;
        case LOADER_ERR_INVALID_DATA:
            return ERR_INVALID_ARGS;
        case LOADER_ERR_ALREADY_EXISTS:
            return ERR_APP_EXISTS;
        case LOADER_ERR_NOT_FOUND:
            return ERR_APP_NOT_FOUND;
        case LOADER_ERR_BUSY:
            return ERR_APP_RUNNING;
        case LOADER_ERR_INTERNAL:
            return ERR_SERVER;
        default:
            return ERR_INVALID_RSP;
    }
}

static int convert_err(int err) {
    switch (err) {
        case TRUSTY_LOADER_NO_ERROR:
            return NO_ERROR;
        case TRUSTY_LOADER_ERR_IPC:
            return ERR_TIPC;
        case TRUSTY_LOADER_ERR_INVALID_RSP:
            return ERR_INVALID_RSP;
        default:
            return ERR_INVALID_ARGS;
    }
}

struct tipc_ctx {
    int fd;
    struct ipc_obj obj;
};

static int get_max_tipc_size(__attribute__((unused)) struct ipc_obj* obj) {
    return MAX_TIPC_PAYLOAD_SIZE;
}

static int send_handler(struct ipc_obj* obj, const void* data, int size) {
    struct tipc_ctx* ctx = containerof(obj, struct tipc_ctx, obj);

    return write(ctx->fd, data, size);
}

static int recv_handler(struct ipc_obj* obj, void* data, int size) {
    struct tipc_ctx* ctx = containerof(obj, struct tipc_ctx, obj);

    return read(ctx->fd, data, size);
}

int loader_load(const char* dev_name, const char* file_name) {
    int rc;
    int ret;
    int rsp;
    int read_bytes;
    int app_fd;
    struct stat st;
    uint32_t app_size;
    uint8_t* app_buf;
    struct tipc_ctx ctx;

    app_fd = open(file_name, O_RDONLY);
    if (app_fd == -1) {
        return ERR_INPUT;
    }

    if (fstat(app_fd, &st) == -1) {
        ret = ERR_INPUT;
        goto err_stat;
    }
    app_size = st.st_size;

    app_buf = malloc(app_size);
    if (!app_buf) {
        ret = ERR_NO_MEM;
        goto err_alloc;
    }

    read_bytes = read(app_fd, app_buf, app_size);
    if (read_bytes != app_size) {
        ret = ERR_INPUT;
        goto err_read;
    }

    rc = tipc_connect(dev_name, LOADER_PORT);
    if (rc < 0) {
        ret = ERR_TIPC;
        goto err_connect;
    }

    ctx.fd = rc;
    ctx.obj.get_max_msg_size = get_max_tipc_size;
    ctx.obj.send = send_handler;
    ctx.obj.recv = recv_handler;

    rc = trusty_loader_load(&ctx.obj, app_buf, app_size, &rsp);
    if (rc != TRUSTY_LOADER_NO_ERROR) {
        ret = convert_err(rc);
    } else {
        ret = rsp_to_loader_err(rsp);
    }

    tipc_close(ctx.fd);

err_connect:
err_read:
    free(app_buf);
err_alloc:
err_stat:
    close(app_fd);
    return ret;
}

int loader_unload(const char* dev_name, const char* uuid_str) {
    int rc;
    int ret;
    int rsp;
    struct tipc_ctx ctx;

    rc = tipc_connect(dev_name, LOADER_PORT);
    if (rc < 0) {
        return ERR_TIPC;
    }

    ctx.fd = rc;
    ctx.obj.get_max_msg_size = get_max_tipc_size;
    ctx.obj.send = send_handler;
    ctx.obj.recv = recv_handler;

    rc = trusty_loader_unload(&ctx.obj, uuid_str, &rsp);
    if (rc != TRUSTY_LOADER_NO_ERROR) {
        ret = convert_err(rc);
    } else {
        ret = rsp_to_loader_err(rsp);
    }

    tipc_close(ctx.fd);

    return ret;
}

const char* loader_error_to_str(int rsp) {
    switch (rsp) {
        case NO_ERROR:
            return "no error";
        case ERR_INPUT:
            return "error reading input data";
        case ERR_TIPC:
            return "TIPC Error";
        case ERR_SERVER:
            return "internal server error";
        case ERR_INVALID_ARGS:
            return "input data is invalid";
        case ERR_APP_NOT_FOUND:
            return "application not found";
        case ERR_APP_EXISTS:
            return "application already loaded";
        case ERR_APP_RUNNING:
            return "application is currently running";
        case ERR_NO_MEM:
            return "not enough memory";
        case ERR_INVALID_RSP:
            return "received invalid response from the server";
        case ERR_INTERNAL:
            return "internal client error";
        default:
            return "unkown error";
    }
}

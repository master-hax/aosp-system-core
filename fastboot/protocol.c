/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define min(a, b) \
    ({ typeof(a) _a = (a); typeof(b) _b = (b); (_a < _b) ? _a : _b; })
#define round_down(a, b) \
    ({ typeof(a) _a = (a); typeof(b) _b = (b); _a - (_a % _b); })

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sparse/sparse.h>

#include "fastboot.h"

static char ERROR[128];

char *fb_get_error(void)
{
    return ERROR;
}

static int check_response(transport_t *trans, unsigned int size, char *response)
{
    unsigned char status[65];
    int r;

    for(;;) {
        r = trans->read(trans->userdata, status, 64);
        if(r < 0) {
            sprintf(ERROR, "status read failed (%s)", strerror(errno));
            trans->close(trans->userdata);
            return -1;
        }
        status[r] = 0;

        if(r < 4) {
            sprintf(ERROR, "status malformed (%d bytes)", r);
            trans->close(trans->userdata);
            return -1;
        }

        if(!memcmp(status, "INFO", 4)) {
            fprintf(stderr,"(bootloader) %s\n", status + 4);
            continue;
        }

        if(!memcmp(status, "OKAY", 4)) {
            if(response) {
                strcpy(response, (char*) status + 4);
            }
            return 0;
        }

        if(!memcmp(status, "FAIL", 4)) {
            if(r > 4) {
                sprintf(ERROR, "remote: %s", status + 4);
            } else {
                strcpy(ERROR, "remote failure");
            }
            return -1;
        }

        if(!memcmp(status, "DATA", 4) && size > 0){
            unsigned dsize = strtoul((char*) status + 4, 0, 16);
            if(dsize > size) {
                strcpy(ERROR, "data size too large");
                trans->close(trans->userdata);
                return -1;
            }
            return dsize;
        }

        strcpy(ERROR,"unknown status code");
        trans->close(trans->userdata);
        break;
    }

    return -1;
}

static int _command_start(transport_t *trans, const char *cmd, unsigned size,
                          char *response)
{
    int cmdsize = strlen(cmd);
    int r;

    if(response) {
        response[0] = 0;
    }

    if(cmdsize > 64) {
        sprintf(ERROR,"command too large");
        return -1;
    }

    if(trans->write(trans->userdata, cmd, cmdsize) != cmdsize) {
        sprintf(ERROR,"command write failed (%s)", strerror(errno));
        trans->close(trans->userdata);
        return -1;
    }

    return check_response(trans, size, response);
}

static int _command_data(transport_t *trans, const void *data, unsigned size)
{
    int r;

    r = trans->write(trans->userdata, data, size);
    if(r < 0) {
        sprintf(ERROR, "data transfer failure (%s)", strerror(errno));
        trans->close(trans->userdata);
        return -1;
    }
    if(r != ((int) size)) {
        sprintf(ERROR, "data transfer failure (short transfer)");
        trans->close(trans->userdata);
        return -1;
    }

    return r;
}

static int _command_end(transport_t *trans)
{
    int r;
    r = check_response(trans, 0, 0);
    if(r < 0) {
        return -1;
    }
    return 0;
}

static int _command_send(transport_t *trans, const char *cmd,
                         const void *data, unsigned size,
                         char *response)
{
    int r;
    if (size == 0) {
        return -1;
    }

    r = _command_start(trans, cmd, size, response);
    if (r < 0) {
        return -1;
    }

    r = _command_data(trans, data, size);
    if (r < 0) {
        return -1;
    }

    r = _command_end(trans);
    if(r < 0) {
        return -1;
    }

    return size;
}

static int _command_send_no_data(transport_t *trans, const char *cmd,
                                 char *response)
{
    int r;

    return _command_start(trans, cmd, 0, response);
}

int fb_command(transport_t *trans, const char *cmd)
{
    return _command_send_no_data(trans, cmd, 0);
}

int fb_command_response(transport_t *trans, const char *cmd, char *response)
{
    return _command_send_no_data(trans, cmd, response);
}

int fb_download_data(transport_t *trans, const void *data, unsigned size)
{
    char cmd[64];
    int r;

    sprintf(cmd, "download:%08x", size);

    r = _command_send(trans, cmd, data, size, 0);
    if(r < 0) {
        return -1;
    } else {
        return 0;
    }
}

#define TRANS_BUF_SIZE 512
static char trans_buf[TRANS_BUF_SIZE];
static int trans_buf_len;

static int fb_download_data_sparse_write(void *priv, const void *data, int len)
{
    int r;
    transport_t *trans = priv;
    int to_write;
    const char *ptr = data;

    if (trans_buf_len) {
        to_write = min(TRANS_BUF_SIZE - trans_buf_len, len);

        memcpy(trans_buf + trans_buf_len, ptr, to_write);
        trans_buf_len += to_write;
        ptr += to_write;
        len -= to_write;
    }

    if (trans_buf_len == TRANS_BUF_SIZE) {
        r = _command_data(trans, trans_buf, TRANS_BUF_SIZE);
        if (r != TRANS_BUF_SIZE) {
            return -1;
        }
        trans_buf_len = 0;
    }

    if (len > TRANS_BUF_SIZE) {
        if (trans_buf_len > 0) {
            sprintf(ERROR, "internal error: trans_buf not empty\n");
            return -1;
        }
        to_write = round_down(len, TRANS_BUF_SIZE);
        r = _command_data(trans, ptr, to_write);
        if (r != to_write) {
            return -1;
        }
        ptr += to_write;
        len -= to_write;
    }

    if (len > 0) {
        if (len > TRANS_BUF_SIZE) {
            sprintf(ERROR, "internal error: too much left for trans_buf\n");
            return -1;
        }
        memcpy(trans_buf, ptr, len);
        trans_buf_len = len;
    }

    return 0;
}

static int fb_download_data_sparse_flush(transport_t *trans)
{
    int r;

    if (trans_buf_len > 0) {
        r = _command_data(trans, trans_buf, trans_buf_len);
        if (r != trans_buf_len) {
            return -1;
        }
        trans_buf_len = 0;
    }

    return 0;
}

int fb_download_data_sparse(transport_t *trans, struct sparse_file *s)
{
    char cmd[64];
    int r;
    int size = sparse_file_len(s, true, false);
    if (size <= 0) {
        return -1;
    }

    sprintf(cmd, "download:%08x", size);
    r = _command_start(trans, cmd, size, 0);
    if (r < 0) {
        return -1;
    }

    r = sparse_file_callback(s, true, false, fb_download_data_sparse_write, trans);
    if (r < 0) {
        return -1;
    }

    fb_download_data_sparse_flush(trans);

    return _command_end(trans);
}

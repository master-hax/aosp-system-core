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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "fastboot.h"

static char ERROR[MAX_ERROR_STRLEN];

char *fb_get_error(void)
{
    return ERROR;
}

static int check_response(usb_handle *usb, size_t size, 
                          unsigned data_okay, char *response, size_t maxLen)
{
    unsigned char status[65] = {0};
    int r;

    for (;;) {
        r = usb_read(usb, status, 64);
        if (r < 0) {
            snprintf(ERROR, MAX_ERROR_STRLEN, "status read failed (%s)",
		strerror(errno));
		
            usb_close(usb);
            return -1;
        }
        status[r] = '\0';

        if (r < 4) {
            snprintf(ERROR, MAX_ERROR_STRLEN, "status malformed (%d bytes)", r);
            usb_close(usb);
            return -1;
        }

        if (memcmp(status, "INFO", 4) == 0) {
            fprintf(stderr,"%s\n", status);
            continue;
        }

        if (memcmp(status, "OKAY", 4) == 0) {
            if (response != NULL) {
                strncpy(response, (char*) status + 4, maxLen);
            }
            return 0;
        }

        if (memcmp(status, "FAIL", 4) == 0) {
            if (r > 4) {
                snprintf(ERROR, MAX_ERROR_STRLEN, "remote: %s", status + 4);
            } else {
                strncpy(ERROR, "remote failure", MAX_ERROR_STRLEN);
            }
            return -1;
        }

        if ((memcmp(status, "DATA", 4) == 0) && (data_okay != 0)){
            unsigned long dsize = strtoul((char *) status + 4, 0, 16);
            if (dsize > size) {
                strncpy(ERROR, "data size too large", MAX_ERROR_STRLEN);
                usb_close(usb);
                return -1;
            }
	    /* XXX: returning unsigned value */
            return dsize;
        }

        strncpy(ERROR, "unknown status code", MAX_ERROR_STRLEN);
        usb_close(usb);
        break;
    }

    return -1;
}

static int _command_send(usb_handle *usb, const char *cmd,
                         const void *data, size_t size,
                         char *response, size_t maxLen)
{
    size_t cmdsize = strlen(cmd);
    int r;
    
    if (response != NULL) {
        response[0] = '\0';
    }

    /* XXX: magic 64 */
    if (cmdsize > 64) {
        snprintf(ERROR, MAX_ERROR_STRLEN, "command too large");
        return -1;
    }

    if (usb_write(usb, cmd, cmdsize) != cmdsize) {
        snprintf(ERROR, MAX_ERROR_STRLEN, "command write failed (%s)",
	    strerror(errno));
	    
        usb_close(usb);
        return -1;
    }

    if (data == NULL) {
        return check_response(usb, size, 0, response, maxLen);
    }

    r = check_response(usb, size, 1, NULL, 0);
    if (r < 0) {
        return -1;
    }
    size = (size_t)r;

    if (size != 0) {
        r = usb_write(usb, data, size);
        if (r < 0) {
            snprintf(ERROR, MAX_ERROR_STRLEN, "data transfer failure (%s)",
		strerror(errno));
		
            usb_close(usb);
            return -1;
        }
        if (r != ((int) size)) {
            snprintf(ERROR, MAX_ERROR_STRLEN, "data transfer failure (short transfer)");
            usb_close(usb);
            return -1;
        }
    }
    
    r = check_response(usb, 0, 0, NULL, 0);
    if (r < 0) {
        return -1;
    } else {
        return size;
    }
}

int fb_command(usb_handle *usb, const char *cmd)
{
    return _command_send(usb, cmd, NULL, 0, NULL, 0);
}

int fb_command_response(usb_handle *usb, const char *cmd, char *response,
    size_t maxLen)
{
    return _command_send(usb, cmd, NULL, 0, response, maxLen);
}

int fb_download_data(usb_handle *usb, const void *data, size_t size)
{
    char cmd[64];
    int r;
    
    snprintf(cmd, 64, "download:%08x", size);
    r = _command_send(usb, cmd, data, size, NULL, 0);
    
    if (r < 0) {
        return -1;
    } else {
        return 0;
    }
}


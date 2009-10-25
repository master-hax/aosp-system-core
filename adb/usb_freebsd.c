/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#include "sysdeps.h"
#include "adb.h"

/* usb scan debugging is waaaay too verbose */
#define DBGX(x...)

void usb_cleanup()
{
}

int usb_write(usb_handle *h, const void *_data, int len)
{
    return 1;
}

int usb_read(usb_handle *h, void *_data, int len)
{
    return 1;
}

void usb_kick(usb_handle *h)
{
}

int usb_close(usb_handle *h)
{
    return 1;
}

void* device_poll_thread(void* unused)
{
    return NULL;
}

void usb_init()
{
}


/*
 *  sync.c
 *
 *   Copyright 2012 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fcntl.h>
#include <stdint.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <sync/sync.h>

int sync_wait(int fd)
{
    return ioctl(fd, SYNC_IOC_WAIT);
}

int sw_sync_obj_create(void)
{
    return open("/dev/sw_sync", O_RDWR);
}

int sw_sync_obj_inc(int fd, unsigned count)
{
    __u32 arg = count;

    return ioctl(fd, SW_SYNC_IOC_INC, &arg);
}

int sw_sync_pt_create(int fd, unsigned value)
{
    __u32 arg = value;
    int err;

    err = ioctl(fd, SW_SYNC_IOC_CREATE_PT, &arg);
    if (err < 0)
        return err;

    return arg;
}

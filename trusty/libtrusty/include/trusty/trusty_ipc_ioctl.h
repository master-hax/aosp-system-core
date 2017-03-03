/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef _TRUSTY_IPC_IOCTL_H
#define _TRUSTY_IPC_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define TIPC_IOC_MAGIC 'r'
#define TIPC_IOC_CONNECT _IOW(TIPC_IOC_MAGIC, 0x80, char *)

#define TIPC_MEMREF_PERM_RO (0x0 << 0)
#define TIPC_MEMREF_PERM_RW (0x1 << 0)

struct tipc_shmem {
    __u32 flags;
    __u32 size[3];
    __u64 base[3];
};

struct tipc_send_msg_req {
    __u64 msgiov;
    __u64 shmemv;
    __u32 msgiov_cnt;
    __u32 shmemv_cnt;
};

#define TIPC_IOC_SEND_MSG _IOW(TIPC_IOC_MAGIC, 0x81, struct tipc_send_msg_req)

#endif

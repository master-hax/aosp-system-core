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

#ifndef _INIT_DEVICES_H
#define _INIT_DEVICES_H

#include <sys/stat.h>

#define DEV_NAME_LEN       12
#define MAX_DEV            16
#define MAX_DEV_PATH       512

extern void handle_device_fd();
struct uevent {
    const char *action;
    const char *path;
    const char *subsystem;
    const char *firmware;
    const char *partition_name;
    const char *device_name;
    const char *country;
    const char *modalias;
    const char *product;
    int partition_num;
    int major;
    int minor;
};

extern void handle_events_fd(void (*handle_event_fp)(struct uevent*));
extern void handle_device_crda_event(struct uevent *uevent);
extern void handle_modalias_triggers(const char* modalias);
extern void device_init(void);
extern int add_dev_perms(const char *name, const char *attr,
                         mode_t perm, unsigned int uid,
                         unsigned int gid, unsigned short prefix);
extern int add_inet_args(char *net_link, char *if_name, char *target_name);
extern int add_dev_args(unsigned int vid, unsigned int pid, char *dev_name, char *target_name);

int get_device_fd();

#endif	/* _INIT_DEVICES_H */

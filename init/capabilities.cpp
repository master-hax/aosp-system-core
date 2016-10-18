// Copyright (C) 2016 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "capabilities.h"

#include <linux/capability.h>
#include <stdlib.h>
#include <string.h>

#include <android-base/macros.h>

struct cap_map_entry {
    int val;
    const char *name;
};

#define CAP_MAP_ENTRY(cap) { CAP_ ## cap, #cap }

static const struct cap_map_entry cap_map[] = {
    CAP_MAP_ENTRY(CHOWN),
    CAP_MAP_ENTRY(DAC_OVERRIDE),
    CAP_MAP_ENTRY(DAC_READ_SEARCH),
    CAP_MAP_ENTRY(FOWNER),
    CAP_MAP_ENTRY(FSETID),
    CAP_MAP_ENTRY(KILL),
    CAP_MAP_ENTRY(SETGID),
    CAP_MAP_ENTRY(SETUID),
    CAP_MAP_ENTRY(SETPCAP),
    CAP_MAP_ENTRY(LINUX_IMMUTABLE),
    CAP_MAP_ENTRY(NET_BIND_SERVICE),
    CAP_MAP_ENTRY(NET_BROADCAST),
    CAP_MAP_ENTRY(NET_ADMIN),
    CAP_MAP_ENTRY(NET_RAW),
    CAP_MAP_ENTRY(IPC_LOCK),
    CAP_MAP_ENTRY(IPC_OWNER),
    CAP_MAP_ENTRY(SYS_MODULE),
    CAP_MAP_ENTRY(SYS_RAWIO),
    CAP_MAP_ENTRY(SYS_CHROOT),
    CAP_MAP_ENTRY(SYS_PTRACE),
    CAP_MAP_ENTRY(SYS_PACCT),
    CAP_MAP_ENTRY(SYS_ADMIN),
    CAP_MAP_ENTRY(SYS_BOOT),
    CAP_MAP_ENTRY(SYS_NICE),
    CAP_MAP_ENTRY(SYS_RESOURCE),
    CAP_MAP_ENTRY(SYS_TIME),
    CAP_MAP_ENTRY(SYS_TTY_CONFIG),
    CAP_MAP_ENTRY(MKNOD),
    CAP_MAP_ENTRY(LEASE),
    CAP_MAP_ENTRY(AUDIT_WRITE),
    CAP_MAP_ENTRY(AUDIT_CONTROL),
    CAP_MAP_ENTRY(SETFCAP),
    CAP_MAP_ENTRY(MAC_OVERRIDE),
    CAP_MAP_ENTRY(MAC_ADMIN),
    CAP_MAP_ENTRY(SYSLOG),
    CAP_MAP_ENTRY(WAKE_ALARM),
    CAP_MAP_ENTRY(BLOCK_SUSPEND),
    CAP_MAP_ENTRY(AUDIT_READ),
};

int lookup_cap(const std::string& cap_name) {
    for (size_t i = 0; i < arraysize(cap_map); i++) {
        if (cap_name == cap_map[i].name)
            return cap_map[i].val;
    }

    return -1;
}

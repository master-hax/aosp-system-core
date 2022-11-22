/*
 * Copyright (C) 2022 The Android Open Source Project
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

#ifndef ERROR
#define ERROR (-1)
#endif
#ifndef NO_ERROR
#define NO_ERROR (0)
#endif

#define LOCAL_TRACE_LEVEL (0)

#ifdef __cplusplus
extern "C" {
#endif

bool debug_silent(void);

#define DBGTRC(_dbglvl_, _fmt_, ...)                               \
    do {                                                           \
        if ((!debug_silent()) && (_dbglvl_ < LOCAL_TRACE_LEVEL)) { \
            printf(_fmt_, ##__VA_ARGS__);                          \
            fflush(stdout);                                        \
        }                                                          \
    } while (0)

#define TIPC_DEFAULT_DEVNAME "/dev/trusty-ipc-dev0"

#ifndef TRUSTY_MAX_CPUS
#define TRUSTY_MAX_CPUS (4)
#endif /* TRUSTY_MAX_CPUS */

/* Trusty thread priority */
#define TRUSTY_NUM_PRIORITIES 32
#define TRUSTY_LOWEST_PRIORITY 0
#define TRUSTY_HIGHEST_PRIORITY (TRUSTY_NUM_PRIORITIES - 1)
#define TRUSTY_LOW_PRIORITY (TRUSTY_NUM_PRIORITIES / 4)
#define TRUSTY_HIGH_PRIORITY ((TRUSTY_NUM_PRIORITIES / 4) * 3)

/* Trusty shadow priority */
#define TRUSTY_SHADOW_PRIORITY_LOW 1
#define TRUSTY_SHADOW_PRIORITY_NORMAL 2
#define TRUSTY_SHADOW_PRIORITY_HIGH 3

#define SHPRIO_DEBUGFS_PATH "/sys/kernel/debug/trusty-sched-share/shadow-priority"

#define SHPRIO_DEBUGFS_MAX_LINE_SIZE (64)

void shprio_debugfs_init(void);
void shprio_debugfs_fini(void);

uint shprio_debugfs_get_cpu_count(void);
uint shprio_debugfs_map_shadow_priority(uint priority);

int shprio_debugfs_get_shadow_priority(uint cpu_id, uint* shprio_p);

#ifdef __cplusplus
}
#endif

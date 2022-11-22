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

#ifndef _SHADOPRIO_TEST_H
#define _SHADOPRIO_TEST_H

#ifndef ERROR
#define ERROR (-1)
#endif
#ifndef NO_ERROR
#define NO_ERROR (0)
#endif

#define LOCAL_TRACE_LEVEL (20)

#define VERIFY_WITH_DEBUGFS (0)

#ifdef __cplusplus
extern "C" {
#endif

#define DBGTRC(_dbglvl_, _fmt_, ...)                           \
    do {                                                       \
        if ((!opt_silent) && (_dbglvl_ < LOCAL_TRACE_LEVEL)) { \
            printf(_fmt_, ##__VA_ARGS__);                      \
            fflush(stdout);                                    \
        }                                                      \
    } while (0)

#define SERVICE_REQ_SET_PRIORITY (1)

struct service_req_pkt {
    uint service_req_id;
    uint cpu_id;
    uint priority;
};

#if VERIFY_WITH_DEBUGFS
void debugfs_init(void);
uint debugfs_get_cpu_count(void);
uint debugfs_get_shadow_priority(uint cpu_id);
#endif /* VERIFY_WITH_DEBUGFS */

#ifdef __cplusplus
}
#endif

#endif /* _SHADOPRIO_TEST_H */

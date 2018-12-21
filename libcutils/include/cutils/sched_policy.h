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

#ifndef __CUTILS_SCHED_POLICY_H
#define __CUTILS_SCHED_POLICY_H

#ifdef __cplusplus
extern "C" {
#endif

/* Keep in sync with THREAD_GROUP_* in frameworks/base/core/java/android/os/Process.java */
typedef enum {
    SP_DEFAULT = -1,
    SP_BACKGROUND = 0,
    SP_FOREGROUND = 1,
    SP_SYSTEM = 2,  // can't be used with set_sched_policy()
    SP_AUDIO_APP = 3,
    SP_AUDIO_SYS = 4,
    SP_TOP_APP = 5,
    SP_RT_APP = 6,
    SP_RESTRICTED = 7,
    SP_CNT,
    SP_MAX = SP_CNT - 1,
    SP_SYSTEM_DEFAULT = SP_FOREGROUND,
} SchedPolicy;

/* For sched_policy functions please include processgroup/sched_policy_ctrl.h */

#ifdef __cplusplus
}
#endif

#endif /* __CUTILS_SCHED_POLICY_H */ 

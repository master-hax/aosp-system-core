/*
 *  sync.h
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

#ifndef __SYS_CORE_SYNC_H
#define __SYS_CORE_SYNC_H

#include <linux/sync.h>
#include <linux/sw_sync.h>

__BEGIN_DECLS

int sync_wait(int fd);

/* sw_sync is mainly inteded for testing and should not be complied into
 * production kernels
 */

int sw_sync_obj_create(void);
int sw_sync_obj_inc(int fd, unsigned count);
int sw_sync_pt_create(int fd, unsigned value);

__END_DECLS

#endif /* __SYS_CORE_SYNC_H */

/*
 * Copyright (C) 2011 The Android Open Source Project
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

#ifndef __TRANSPORT_H
#define __TRANSPORT_H

#include <sys/types.h>

#include "adb.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Convenience wrappers around read/write that will retry on
 * EINTR and/or short read/write.  Returns 0 on success, -1
 * on error or EOF.
 *
 * TODO(danalbert): Just kill theses and use TEMP_FAILURE_RETRY.
 */
int readx(int fd, void *ptr, size_t len);
int writex(int fd, const void *ptr, size_t len);

/*
 * Obtain a transport from the available transports.
 * If state is != CS_ANY, only transports in that state are considered.
 * If serial is non-NULL then only the device with that serial will be chosen.
 * If no suitable transport is found, error is set.
 */
atransport *acquire_one_transport(int state, transport_type ttype, const char* serial, char **error_out);
void add_transport_disconnect( atransport*  t, adisconnect*  dis );
void remove_transport_disconnect( atransport*  t, adisconnect*  dis );
void kick_transport( atransport*  t );
void run_transport_disconnects( atransport*  t );

#ifdef __cplusplus
}
#endif

#endif   /* __TRANSPORT_H */

/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef _GETEVENT_H_
#define _GETEVENT_H_

#include <keychord/keychord.h>

#include "libkeychord.h"

#ifndef LIBKEYCHORD_HIDDEN
#define LIBKEYCHORD_HIDDEN __attribute__((visibility("hidden")))
#endif

extern keychord_register_epoll_handler_fn KeychordRegisterEpollHandler;
extern keychord_unregister_epoll_handler_fn KeychordUnregisterEpollHandler;

LIBKEYCHORD_HIDDEN event_code_t KeychordCodeMax(event_type_t type);
LIBKEYCHORD_HIDDEN int KeychordGeteventEnable(void);

#endif /* _GETEVENT_H_ */

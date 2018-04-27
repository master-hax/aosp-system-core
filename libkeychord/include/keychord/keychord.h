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

#ifndef _KEYCHORD_H_
#define _KEYCHORD_H_

#include <linux/input.h>
#include <stdbool.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

/* epoll callback function prototypes */
typedef void (*keychord_epoll_handler_fn)(void);
typedef int (*keychord_register_epoll_handler_fn)(keychord_epoll_handler_fn handler, int fd,
                                                  const char* name);
typedef int (*keychord_unregister_epoll_handler_fn)(int fd, const char* name);

/* limit the number of epoll handlers (max # devices in /dev/input/) */
#define KEYCHORD_MAX_EPOLL_HANDLERS 32

/*
 * Sets up the session, returns session descriptor (always zero for now)
 * on success returns a positive value.
 */
int keychord_init(keychord_register_epoll_handler_fn register_epoll_handler,
                  keychord_unregister_epoll_handler_fn unregister_epoll_handler);
/* Session descriptor in d (must be zero for now, use above return value) */
int keychord_release(int d);

/* event callback function prototype */
typedef int (*keychord_event_handler_fn)(const struct input_event* event, int fd, const char* name);
/*
 * Actually opens and starts events callback.
 * Returns -1 if using keychord driver.
 */

int keychord_register_event_handler(int d, keychord_event_handler_fn event_handler);

/* function active after keychord_register_event_handler() */
bool keychord_get_event_active(int d, int idx);
int keychord_get_event_fd(int d, int idx);
bool keychord_get_event_available(int d, int idx, int type, int code);
int keychord_get_event_version(int d, int idx);
bool keychord_get_event_current(int d, int type, int code);

/*
 * Reference below can disappear after epoll_wait handling, or asynchronously
 * during keychord_run.  Never use this API if epoll asynchronous.
 */
const char* keychord_get_event_name(int d, int idx);

/*
 * Sets the code individually or in a group and returns id.  If using the
 * keychord driver from the kernel, the code must by EV_KEY, num_keycodes
 * must be 1 and duration_ms must be -1.
 *
 * Assumption is all codes are retrieved in keychord_callback_event, until the
 * first call, then list is limited.
 */
int keychord_enable(int d, int code, const int* keycodes, size_t num_keycodes, int duration_ms);

/* function active after keychord_enable() */
bool keychord_get_event_mask(int d, int type, int code);

/* deregisters the keychord id (returns -1 if using keychord driver) */
int keychord_disable(int d, int id);

/* keychord if callback function prototype */
typedef int (*keychord_id_handler_fn)(int id);
/* actually open and starts the keycodes callback, returns failure if non registered */
int keychord_register_id_handler(int d, keychord_id_handler_fn id_handler);

/* default handlers */
int keychord_default_reset_epoll_fd(int fd);
void keychord_default_clear_epoll();
int keychord_default_register_epoll_handler(keychord_epoll_handler_fn fn, int fd, const char* name);
int keychord_default_unregister_epoll_handler(int fd, const char* name);
int keychord_default_epoll_wait(int epoll_timeout_ms);
int keychord_timeout_ms(int epoll_timeout_ms);

int keychord_run(int d, const char* threadname);
int keychord_stop(int d);

__END_DECLS

#ifdef __cplusplus
extern "C++" { /* In case this included wrapped with __BEGIN_DECLS */

#include <chrono>
#include <vector>

int keychord_init();

int keychord_enable(int d, int type /* = EV_KEY */, std::vector<int>& keycodes,
                    std::chrono::milliseconds duration = std::chrono::milliseconds::zero());

std::chrono::milliseconds keychord_default_epoll_wait(std::chrono::milliseconds epoll_timeout);

std::chrono::milliseconds keychord_timeout(std::chrono::milliseconds epoll_timeout);

std::vector<bool> keychord_get_event_active(int d);
std::vector<bool> keychord_get_event_available(int d);
bool keychord_get_event_available(int d, int idx);
std::string keychord_get_event_name_string(int d, int idx);
const std::vector<bool>& keychord_get_event_available(int d, int idx, int type);
const std::vector<bool>& keychord_get_event_current(int d, int type = EV_KEY);
std::vector<bool> keychord_get_event_mask(int d, int type = EV_KEY);

__BEGIN_DECLS
int keychord_enable(int d, int code /* = EV_KEY */, const int* keycodes, size_t num_keycodes,
                    int duration_ms = 0);
int keychord_run(int d = 0, const char* threadname = nullptr);
int keychord_stop(int d = 0);
__END_DECLS

} /* extern "C++" */
#endif /* __cplusplus */

#endif /* _KEYCHORD_H_ */

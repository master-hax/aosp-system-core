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

#ifndef NATIVE_HANDLE_FDSAN_H_
#define NATIVE_HANDLE_FDSAN_H_

#include <cutils/native_handle.h>

/*
 * this file contains helper functions for applying fdsan protection to file
 * descriptors wrapped within a native_handle_t, to help catch errors like
 * double close, etc.
 * consider adopting it by adding a call to native_handle_set_fdsan_tag()
 * after fds in a native_handle_t are populated, and replacing the call to
 * native_handle_close() with native_handle_close_with_tag().
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * native_handle_set_fdsan_tag
 *
 * updates the fdsan tag for any fds contained in the supplied native_handle_t
 * to indicate that they are owned by this native_handle_t and should only be
 * closed via native_handle_close_with_tag().
 */
void native_handle_set_fdsan_tag(const native_handle_t* handle);

/*
 * native_handle_unset_fdsan_tag
 *
 * clears the fdsan tag for any file descriptors contained in the supplied
 * native_handle_t. Should be used if this native_handle_t does not own the
 * contained file descriptors, but the fdsan tags were previously set, such
 * as via native_handle_set_fdsan_tag().
 */
void native_handle_unset_fdsan_tag(const native_handle_t* handle);

/*
 * native_handle_close_with_tag
 *
 * equivalent to native_handle_close(), but does not permit the file
 * descriptors to be untagged. Use if it's known that the fds in this
 * native_handle_t were previously tagged via native_handle_set_tag().
 */
int native_handle_close_with_tag(const native_handle_t* h);

#ifdef __cplusplus
}
#endif

#endif /* NATIVE_HANDLE_FDSAN_H_ */

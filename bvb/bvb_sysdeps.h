/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef _BVB_SYSDEPS_H
#define _BVB_SYSDEPS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Change these includes to match your platform to bring in the
 * equivalent types available in a normal C runtime.
 */
#include <stddef.h>
#include <stdint.h>

/* Debug and error output */
#ifdef BVB_ENABLE_DEBUG
#define BVB_DEBUG(params) bvb_debug params
#else
#define BVB_DEBUG(params)
#endif

#ifdef BVB_DEBUG
#define bvb_assert(expr) do { if (!(expr)) { \
    bvb_error("assert fail: %s at %s:%d\n", \
              #expr, __FILE__, __LINE__); }} while(0)
#else
#define bvb_assert(expr)
#endif

/*
 * Compare |n| bytes in |src1| and |src2|.
 *
 * Returns an integer less than, equal to, or greater than zero if the first
 * |n| bytes of |src1| is found, respectively, to be less than, to match, or be
 * greater than the first |n| bytes of |src2|. */
int bvb_memcmp(const void* src1, const void* src2, size_t n);

/*
 * Copy |n| bytes from |src| to |dest|.
 */
void* bvb_memcpy(void* dest, const void* src, size_t n);

/*
 * Set |n| bytes starting at |s| to |c|.  Returns |dest|.
 */
void* bvb_memset(void* dest, const int c, size_t n);

/*
 * Compare |n| bytes starting at |s1| with |s2| and return 0 if they
 * match, 1 if they don't.  Returns 0 if |n|==0, since no bytes mismatched.
 *
 * Time taken to perform the comparison is only dependent on |n| and
 * not on the relationship of the match between |s1| and |s2|.
 *
 * Note that unlike bvb_memcmp(), this only indicates inequality, not
 * whether |s1| is less than or greater than |s2|.
 */
int bvb_safe_memcmp(const void* s1, const void* s2, size_t n);

void bvb_error(const char* format, ...);
void bvb_debug(const char* format, ...);
void bvb_printf(const char* format, ...);

void* bvb_malloc(size_t size);
void bvb_free(void* ptr);

size_t bvb_strlen(const char* str);

#ifdef __cplusplus
}
#endif

#endif  /* _BVB_SYSDEPS_H */

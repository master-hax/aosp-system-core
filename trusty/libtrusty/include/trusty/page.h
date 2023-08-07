new file mode regular(100644)
/*
 * Copyright (C) 2023 The Android Open Source Project
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
#ifndef _LIB_TRUSTY_PAGE_H
#define _LIB_TRUSTY_PAGE_H
#ifdef __cplusplus
extern "C" {
#endif

static inline size_t RoundPageUp(size_t size) {
    static size_t pagesize = getpagesize();
    return (size + (pagesize - 1)) & ~(pagesize - 1);
}

#ifdef __cplusplus
}
#endif
#endif

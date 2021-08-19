/*
 *  userpanic.h
 *
 *   Copyright 2021 Google, Inc
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

#ifndef __SYS_CORE_USERPANIC_H
#define __SYS_CORE_USERPANIC_H

__BEGIN_DECLS

#ifdef __cplusplus
extern "C" {
#endif

void android_panic_kernel(const char *title, const char *msg = NULL);

#ifdef __cplusplus
}
#endif

__END_DECLS

#endif /* __SYS_CORE_USERPANIC_H */

/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef SERVICES_H_
#define SERVICES_H_

struct stinfo {
    void (*func)(int fd, void *cookie);
    int fd;
    void *cookie;
};

void service_bootstrap_func(void* x);
int create_service_thread(void (*func)(int, void *), void *cookie);

int service_to_fd_shared(const char* name, const atransport* transport);

#endif  // SERVICES_H_

/*
 * Copyright (C) 2017 The Android Open Source Project
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
#include "linker.h"

#include <android/dlext.h>
#include <dlfcn.h>

#define LOG_TAG "vndksupport"
#include <log/log.h>
#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>

__attribute__((weak)) extern struct android_namespace_t* android_get_exported_namespace(const char*);
__attribute__((weak)) extern void* android_dlopen_ext(const char*, int, const android_dlextinfo*);

static const char* g_namespace_name = NULL;
static struct android_namespace_t* g_vendor_namespace = NULL;

static void init_vendor_namespace() {
    static const char* const names[] = {"sphal", "default", NULL};
    for (int name_idx = 0; names[name_idx] != NULL; ++name_idx) {
        struct android_namespace_t* ns = NULL;
        if (android_get_exported_namespace != NULL) {
            ns = android_get_exported_namespace(names[name_idx]);
        }
        if (ns != NULL) {
            g_vendor_namespace = ns;
            g_namespace_name = names[name_idx];
            break;
        }
    }
}

static struct android_namespace_t* get_vendor_namespace() {
    static pthread_once_t once_control = PTHREAD_ONCE_INIT;
    pthread_once(&once_control, init_vendor_namespace);
    return g_vendor_namespace;
}

int android_is_in_vendor_process() {
    // Special case init, since when init runs, ld.config.<ver>.txt hasn't been
    // loaded (sysprop service isn't up for init to know <ver>).
    if (getpid() == 1) {
        return 0;
    }
    if (android_get_exported_namespace == NULL) {
        ALOGD("android_get_exported_namespace() not available. Assuming system process.");
        return 0;
    }

    // In vendor process, 'vndk' namespace is not visible, whereas in system
    // process, it is.
    return android_get_exported_namespace("vndk") == NULL;
}

void* android_load_sphal_library(const char* name, int flag) {
    struct android_namespace_t* vendor_namespace = get_vendor_namespace();
    if (vendor_namespace != NULL) {
        const android_dlextinfo dlextinfo = {
            .flags = ANDROID_DLEXT_USE_NAMESPACE, .library_namespace = vendor_namespace,
        };
        void* handle = NULL;
        if (android_dlopen_ext != NULL) {
            handle = android_dlopen_ext(name, flag, &dlextinfo);
        }
        if (!handle) {
            ALOGE("Could not load %s from %s namespace: %s.", name, g_namespace_name, dlerror());
        }
        return handle;
    } else {
        ALOGD("Loading %s from current namespace instead of sphal namespace.", name);
        return dlopen(name, flag);
    }
}

int android_unload_sphal_library(void* handle) {
    return dlclose(handle);
}

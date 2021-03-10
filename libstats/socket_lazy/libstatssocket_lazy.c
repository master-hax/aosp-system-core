/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "libstatssocket_lazy.h"

#include <dlfcn.h>
#include <pthread.h>

#include <stdatomic.h>

#include "log/log.h"

#include "stats_event.h"

// This file provides a lazy interface to libstatssocket.so to address early boot dependencies.
// Specifically bootanimation, surfaceflinger, and lmkd run before the statsd APEX is loaded and
// libstatssocket.so is in the statsd APEX.

// Method pointers to libstatssocket methods are held in an array which simplifies checking
// all pointers are initialized.
enum MethodIndex {
    // Stats Event APIs in stats_event.h.
    k_AStatsEvent_obtain,
    k_AStatsEvent_build,
    k_AStatsEvent_write,
    k_AStatsEvent_release,
    k_AStatsEvent_setAtomId,
    k_AStatsEvent_writeInt32,
    k_AStatsEvent_writeInt64,
    k_AStatsEvent_writeFloat,
    k_AStatsEvent_writeBool,
    k_AStatsEvent_writeByteArray,
    k_AStatsEvent_writeString,
    k_AStatsEvent_writeAttributionChain,
    k_AStatsEvent_addBoolAnnotation,
    k_AStatsEvent_addInt32Annotation,

    // Stats Socket APIs in stats_socket.h.
    k_AStatsSocket_close,

    // Marker for count of methods
    k_MethodCount
};

// Table of methods pointers in libstatssocket APIs.
static void* g_Methods[k_MethodCount];

//
// Libstatssocket lazy loading.
//

static atomic_bool gPreventLibstatssocketLoading = false;  // Allows tests to block loading.

void PreventLibstatssocketLazyLoadingForTests() {
    atomic_store_explicit(&gPreventLibstatssocketLoading, true, memory_order_release);
}

static void* LoadLibstatssocket(int dlopen_flags) {
    if (atomic_load_explicit(&gPreventLibstatssocketLoading, memory_order_acquire)) {
        return NULL;
    }
    return dlopen("libstatssocket.so", dlopen_flags);
}

//
// Initialization and symbol binding.

static void BindSymbol(void* handle, const char* name, enum MethodIndex index) {
    void* symbol = dlsym(handle, name);
    LOG_ALWAYS_FATAL_IF(symbol == NULL, "Failed to find symbol '%s' in libstatssocket.so: %s", name,
                        dlerror());
    g_Methods[index] = symbol;
}

static void InitializeOnce() {
    void* handle = LoadLibstatssocket(RTLD_NOW);
    LOG_ALWAYS_FATAL_IF(handle == NULL, "Failed to load libstatssocket.so: %s", dlerror());

#undef BIND_SYMBOL
#define BIND_SYMBOL(name) BindSymbol(handle, #name, k_##name);
    // Methods in stats_event.h.
    BIND_SYMBOL(AStatsEvent_obtain);
    BIND_SYMBOL(AStatsEvent_build);
    BIND_SYMBOL(AStatsEvent_write);
    BIND_SYMBOL(AStatsEvent_release);
    BIND_SYMBOL(AStatsEvent_setAtomId);
    BIND_SYMBOL(AStatsEvent_writeInt32);
    BIND_SYMBOL(AStatsEvent_writeInt64);
    BIND_SYMBOL(AStatsEvent_writeFloat);
    BIND_SYMBOL(AStatsEvent_writeBool);
    BIND_SYMBOL(AStatsEvent_writeByteArray);
    BIND_SYMBOL(AStatsEvent_writeString);
    BIND_SYMBOL(AStatsEvent_writeAttributionChain);
    BIND_SYMBOL(AStatsEvent_addBoolAnnotation);
    BIND_SYMBOL(AStatsEvent_addInt32Annotation);

    // Methods in stats_socket.h.
    BIND_SYMBOL(AStatsSocket_close);
#undef BIND_SYMBOL

    // Check every symbol is bound.
    for (int i = 0; i < k_MethodCount; ++i) {
        LOG_ALWAYS_FATAL_IF(g_Methods[i] == NULL,
                            "Uninitialized method in libstatssocket_lazy at index: %d", i);
    }
}

static void EnsureInitialized() {
    static pthread_once_t initialized = PTHREAD_ONCE_INIT;
    pthread_once(&initialized, InitializeOnce);
}

#define INVOKE_METHOD(name, method_type, args...) \
    do {                                          \
        EnsureInitialized();                      \
        void* method = g_Methods[k_##name];       \
        return ((method_type)method)(args);       \
    } while (0)

#define INVOKE_VOID_METHOD(name, method_type, args...) \
    do {                                               \
        EnsureInitialized();                           \
        void* method = g_Methods[k_##name];            \
        ((method_type)method)(args);                   \
    } while (0)

//
// Forwarding for methods in stats_event.h.
//

AStatsEvent* AStatsEvent_obtain() {
    typedef AStatsEvent* (*M)();
    INVOKE_METHOD(AStatsEvent_obtain, M);
}

void AStatsEvent_build(AStatsEvent* event) {
    typedef void (*M)(AStatsEvent*);
    INVOKE_VOID_METHOD(AStatsEvent_build, M, event);
}

int AStatsEvent_write(AStatsEvent* event) {
    typedef int (*M)(AStatsEvent*);
    INVOKE_METHOD(AStatsEvent_write, M, event);
}

void AStatsEvent_release(AStatsEvent* event) {
    typedef void (*M)(AStatsEvent*);
    INVOKE_VOID_METHOD(AStatsEvent_release, M, event);
}

void AStatsEvent_setAtomId(AStatsEvent* event, uint32_t atomId) {
    typedef void (*M)(AStatsEvent*, uint32_t);
    INVOKE_VOID_METHOD(AStatsEvent_setAtomId, M, event, atomId);
}

void AStatsEvent_writeInt32(AStatsEvent* event, int32_t value) {
    typedef void (*M)(AStatsEvent*, int32_t);
    INVOKE_VOID_METHOD(AStatsEvent_writeInt32, M, event, value);
}

void AStatsEvent_writeInt64(AStatsEvent* event, int64_t value) {
    typedef void (*M)(AStatsEvent*, int64_t);
    INVOKE_VOID_METHOD(AStatsEvent_writeInt64, M, event, value);
}

void AStatsEvent_writeFloat(AStatsEvent* event, float value) {
    typedef void (*M)(AStatsEvent*, float);
    INVOKE_VOID_METHOD(AStatsEvent_writeFloat, M, event, value);
}

void AStatsEvent_writeBool(AStatsEvent* event, bool value) {
    typedef void (*M)(AStatsEvent*, bool);
    INVOKE_VOID_METHOD(AStatsEvent_writeBool, M, event, value);
}

void AStatsEvent_writeByteArray(AStatsEvent* event, const uint8_t* buf, size_t numBytes) {
    typedef void (*M)(AStatsEvent*, const uint8_t*, size_t);
    INVOKE_VOID_METHOD(AStatsEvent_writeByteArray, M, event, buf, numBytes);
}

void AStatsEvent_writeString(AStatsEvent* event, const char* value) {
    typedef void (*M)(AStatsEvent*, const char*);
    INVOKE_VOID_METHOD(AStatsEvent_writeString, M, event, value);
}

void AStatsEvent_writeAttributionChain(AStatsEvent* event, const uint32_t* uids,
                                       const char* const* tags, uint8_t numNodes) {
    typedef void (*M)(AStatsEvent*, const uint32_t*, const char* const*, uint8_t);
    INVOKE_VOID_METHOD(AStatsEvent_writeAttributionChain, M, event, uids, tags, numNodes);
}

void AStatsEvent_addBoolAnnotation(AStatsEvent* event, uint8_t annotationId, bool value) {
    typedef void (*M)(AStatsEvent*, uint8_t, bool);
    INVOKE_VOID_METHOD(AStatsEvent_addBoolAnnotation, M, event, annotationId, value);
}

void AStatsEvent_addInt32Annotation(AStatsEvent* event, uint8_t annotationId, int32_t value) {
    typedef void (*M)(AStatsEvent*, uint8_t, int32_t);
    INVOKE_VOID_METHOD(AStatsEvent_addInt32Annotation, M, event, annotationId, value);
}

//
// Forwarding for methods in stats_socket.h.
//

void AStatsSocket_close() {
    typedef void (*M)();
    INVOKE_VOID_METHOD(AStatsSocket_close, M);
}
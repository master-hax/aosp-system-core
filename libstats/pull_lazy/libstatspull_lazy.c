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

#include "libstatspull_lazy.h"

#include <dlfcn.h>
#include <pthread.h>

#include <stdatomic.h>

#include "log/log.h"

#include "stats_pull_atom_callback.h"

// This file provides a lazy interface to libstatspull.so to address early boot dependencies.
// Specifically bootanimation, surfaceflinger, and lmkd run before the statsd APEX is loaded and
// libstatspull.so is in the statsd APEX.

// Method pointers to libstatspull methods are held in an array which simplifies checking
// all pointers are initialized.
enum MethodIndex {
    // PullAtomMetadata APIs in stats_pull_atom_callback.h.
    k_AStatsManager_PullAtomMetadata_obtain,
    k_AStatsManager_PullAtomMetadata_release,
    k_AStatsManager_PullAtomMetadata_setCoolDownMillis,
    k_AStatsManager_PullAtomMetadata_getCoolDownMillis,
    k_AStatsManager_PullAtomMetadata_setTimeoutMillis,
    k_AStatsManager_PullAtomMetadata_getTimeoutMillis,
    k_AStatsManager_PullAtomMetadata_setAdditiveFields,
    k_AStatsManager_PullAtomMetadata_getNumAdditiveFields,
    k_AStatsManager_PullAtomMetadata_getAdditiveFields,

    // AStatsEventList APIs in stats_pull_atom_callback.h
    k_AStatsEventList_addStatsEvent,

    // PullAtomCallback APIs in stats_pull_atom_callback.h
    k_AStatsManager_setPullAtomCallback,
    k_AStatsManager_clearPullAtomCallback,

    // Marker for count of methods
    k_MethodCount
};

// Table of methods pointers in libstatspull APIs.
static void* g_Methods[k_MethodCount];

//
// Libstatspull lazy loading.
//

static atomic_bool gPreventLibstatspullLoading = false;  // Allows tests to block loading.

void PreventLibstatspullLazyLoadingForTests() {
    atomic_store_explicit(&gPreventLibstatspullLoading, true, memory_order_release);
}

static void* LoadLibstatspull(int dlopen_flags) {
    if (atomic_load_explicit(&gPreventLibstatspullLoading, memory_order_acquire)) {
        return NULL;
    }
    return dlopen("libstatspull.so", dlopen_flags);
}

//
// Initialization and symbol binding.

static void BindSymbol(void* handle, const char* name, enum MethodIndex index) {
    void* symbol = dlsym(handle, name);
    LOG_ALWAYS_FATAL_IF(symbol == NULL, "Failed to find symbol '%s' in libstatspull.so: %s", name,
                        dlerror());
    g_Methods[index] = symbol;
}

static void InitializeOnce() {
    void* handle = LoadLibstatspull(RTLD_NOW);
    LOG_ALWAYS_FATAL_IF(handle == NULL, "Failed to load libstatspull.so: %s", dlerror());

#undef BIND_SYMBOL
#define BIND_SYMBOL(name) BindSymbol(handle, #name, k_##name);
    // PullAtomMetadata APIs in stats_pull_atom_callback.h.
    BIND_SYMBOL(AStatsManager_PullAtomMetadata_obtain);
    BIND_SYMBOL(AStatsManager_PullAtomMetadata_release);
    BIND_SYMBOL(AStatsManager_PullAtomMetadata_setCoolDownMillis);
    BIND_SYMBOL(AStatsManager_PullAtomMetadata_getCoolDownMillis);
    BIND_SYMBOL(AStatsManager_PullAtomMetadata_setTimeoutMillis);
    BIND_SYMBOL(AStatsManager_PullAtomMetadata_getTimeoutMillis);
    BIND_SYMBOL(AStatsManager_PullAtomMetadata_setAdditiveFields);
    BIND_SYMBOL(AStatsManager_PullAtomMetadata_getNumAdditiveFields);
    BIND_SYMBOL(AStatsManager_PullAtomMetadata_getAdditiveFields);

    // AStatsEventList APIs in stats_pull_atom_callback.h
    BIND_SYMBOL(AStatsEventList_addStatsEvent);

    // PullAtomCallback APIs in stats_pull_atom_callback.h
    BIND_SYMBOL(AStatsManager_setPullAtomCallback);
    BIND_SYMBOL(AStatsManager_clearPullAtomCallback);

#undef BIND_SYMBOL

    // Check every symbol is bound.
    for (int i = 0; i < k_MethodCount; ++i) {
        LOG_ALWAYS_FATAL_IF(g_Methods[i] == NULL,
                            "Uninitialized method in libstatspull_lazy at index: %d", i);
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
// Forwarding for methods in stats_pull_atom_callback.h.
//

AStatsManager_PullAtomMetadata* AStatsManager_PullAtomMetadata_obtain() {
    typedef AStatsManager_PullAtomMetadata* (*M)();
    INVOKE_METHOD(AStatsManager_PullAtomMetadata_obtain, M);
}

void AStatsManager_PullAtomMetadata_release(AStatsManager_PullAtomMetadata* metadata) {
    typedef void (*M)(AStatsManager_PullAtomMetadata*);
    INVOKE_VOID_METHOD(AStatsManager_PullAtomMetadata_release, M, metadata);
}

void AStatsManager_PullAtomMetadata_setCoolDownMillis(AStatsManager_PullAtomMetadata* metadata,
                                                      int64_t cool_down_millis) {
    typedef void (*M)(AStatsManager_PullAtomMetadata*, int64_t);
    INVOKE_VOID_METHOD(AStatsManager_PullAtomMetadata_setCoolDownMillis, M, metadata,
                       cool_down_millis);
}

int64_t AStatsManager_PullAtomMetadata_getCoolDownMillis(AStatsManager_PullAtomMetadata* metadata) {
    typedef int64_t (*M)(AStatsManager_PullAtomMetadata*);
    INVOKE_METHOD(AStatsManager_PullAtomMetadata_getCoolDownMillis, M, metadata);
}

void AStatsManager_PullAtomMetadata_setTimeoutMillis(AStatsManager_PullAtomMetadata* metadata,
                                                     int64_t timeout_millis) {
    typedef void (*M)(AStatsManager_PullAtomMetadata*, int64_t);
    INVOKE_VOID_METHOD(AStatsManager_PullAtomMetadata_setTimeoutMillis, M, metadata,
                       timeout_millis);
}

int64_t AStatsManager_PullAtomMetadata_getTimeoutMillis(AStatsManager_PullAtomMetadata* metadata) {
    typedef int64_t (*M)(AStatsManager_PullAtomMetadata*);
    INVOKE_METHOD(AStatsManager_PullAtomMetadata_getTimeoutMillis, M, metadata);
}

void AStatsManager_PullAtomMetadata_setAdditiveFields(AStatsManager_PullAtomMetadata* metadata,
                                                      int32_t* additive_fields,
                                                      int32_t num_fields) {
    typedef void (*M)(AStatsManager_PullAtomMetadata*, int32_t*, int32_t);
    INVOKE_VOID_METHOD(AStatsManager_PullAtomMetadata_setAdditiveFields, M, metadata,
                       additive_fields, num_fields);
}

int32_t AStatsManager_PullAtomMetadata_getNumAdditiveFields(
        AStatsManager_PullAtomMetadata* metadata) {
    typedef int32_t (*M)(AStatsManager_PullAtomMetadata*);
    INVOKE_METHOD(AStatsManager_PullAtomMetadata_getNumAdditiveFields, M, metadata);
}

void AStatsManager_PullAtomMetadata_getAdditiveFields(AStatsManager_PullAtomMetadata* metadata,
                                                      int32_t* fields) {
    typedef void (*M)(AStatsManager_PullAtomMetadata*, int32_t*);
    INVOKE_VOID_METHOD(AStatsManager_PullAtomMetadata_getTimeoutMillis, M, metadata, fields);
}

AStatsEvent* AStatsEventList_addStatsEvent(AStatsEventList* pull_data) {
    typedef AStatsEvent* (*M)(AStatsEventList*);
    INVOKE_METHOD(AStatsEventList_addStatsEvent, M, pull_data);
}

void AStatsManager_setPullAtomCallback(int32_t atom_tag, AStatsManager_PullAtomMetadata* metadata,
                                       AStatsManager_PullAtomCallback callback, void* cookie) {
    typedef void (*M)(int32_t, AStatsManager_PullAtomMetadata*, AStatsManager_PullAtomCallback,
                      void*);
    INVOKE_VOID_METHOD(AStatsManager_setPullAtomCallback, M, atom_tag, metadata, callback, cookie);
}

void AStatsManager_clearPullAtomCallback(int32_t atom_tag) {
    typedef void (*M)(int32_t);
    INVOKE_VOID_METHOD(AStatsManager_clearPullAtomCallback, M, atom_tag);
}

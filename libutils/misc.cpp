/*
 * Copyright (C) 2005 The Android Open Source Project
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

#define LOG_TAG "misc"

#include <utils/misc.h>

#include <pthread.h>

#include <utils/Log.h>
#include <utils/Vector.h>

#if defined(__ANDROID__) && !defined(__ANDROID_RECOVERY__)
#include <dlfcn.h>
#include <vndksupport/linker.h>
#endif

extern "C" void do_report_sysprop_change();

using namespace android;

namespace android {

struct sysprop_change_callback_info {
    sysprop_change_callback callback;
    int priority;
};

#if !defined(_WIN32)
static pthread_mutex_t gSyspropMutex = PTHREAD_MUTEX_INITIALIZER;
static Vector<sysprop_change_callback_info>* gSyspropList = nullptr;
#endif

#if !defined(_WIN32)
void add_sysprop_change_callback(sysprop_change_callback cb, int priority) {
    pthread_mutex_lock(&gSyspropMutex);
    if (gSyspropList == nullptr) {
        gSyspropList = new Vector<sysprop_change_callback_info>();
    }
    sysprop_change_callback_info info;
    info.callback = cb;
    info.priority = priority;
    bool added = false;
    for (size_t i=0; i<gSyspropList->size(); i++) {
        if (priority >= gSyspropList->itemAt(i).priority) {
            gSyspropList->insertAt(info, i);
            added = true;
            break;
        }
    }
    if (!added) {
        gSyspropList->add(info);
    }
    pthread_mutex_unlock(&gSyspropMutex);
}
#else
void add_sysprop_change_callback(sysprop_change_callback, int) {}
#endif

#if defined(__ANDROID__) && !defined(__ANDROID_RECOVERY__)
void (*get_report_sysprop_change_func())() {
    void (*func)() = nullptr;
    void* handle = android_load_sphal_library("libutils.so", RTLD_NOW);
    if (handle != nullptr) {
        func = reinterpret_cast<decltype(func)>(dlsym(handle, "do_report_sysprop_change"));
    }

    return func;
}
#endif

void report_sysprop_change() {
    do_report_sysprop_change();

#if defined(__ANDROID__) && !defined(__ANDROID_RECOVERY__)
    // libutils.so is double loaded; from the default namespace and from the
    // 'sphal' namespace. Redirect the sysprop change event to the other instance
    // of libutils.so loaded in the 'sphal' namespace so that listeners attached
    // to that instance is also notified with this event.
    static auto func = get_report_sysprop_change_func();
    if (func != nullptr) {
        (*func)();
    }
#endif
}

};  // namespace android

void do_report_sysprop_change() {
#if !defined(_WIN32)
    pthread_mutex_lock(&gSyspropMutex);
    Vector<sysprop_change_callback_info> listeners;
    if (gSyspropList != nullptr) {
        listeners = *gSyspropList;
    }
    pthread_mutex_unlock(&gSyspropMutex);

    //ALOGI("Reporting sysprop change to %d listeners", listeners.size());
    for (size_t i=0; i<listeners.size(); i++) {
        listeners[i].callback();
    }
#endif
}

// experimental

class __attribute__((capability("property"))) State {
  public:
    void Start() __attribute__((acquire_capability)) {}
    void End() __attribute__((release_capability)) {}

  private:
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-private-field"
    int size[0];
#pragma clang diagnostic pop
};
static_assert(sizeof(State) == 0);

#define DECLARE_STATE(X) State _state_##X
#define ENTER_STATE(X) __attribute__((acquire_capability(_state_##X)))
#define LEAVE_STATE(X) __attribute__((release_capability(_state_##X)))
#define REQUIRE_STATE(X) __attribute__((requires_capability(_state_##X)))

#define START_STATE(X) _state_##X.Start()
#define END_STATE(X) _state_##X.End()

class ClassWithBuilder {
  public:
    ClassWithBuilder() ENTER_STATE(Constructing) { START_STATE(Constructing); }

    void SetName(const std::string& name) REQUIRE_STATE(Constructing) { mName = name; }

    void init() LEAVE_STATE(Constructing) ENTER_STATE(Running) {
        END_STATE(Constructing);
        START_STATE(Running);

        // imagine we start a thread
    }

    void doSomethingWhileRunning() REQUIRE_STATE(Running) {
        // guaranteed that init has been called
    }

  private:
    DECLARE_STATE(Constructing);
    DECLARE_STATE(Running);

    std::string mName;
};

// the magic of 0-sized structures!
static_assert(sizeof(ClassWithBuilder) == sizeof(std::string));
static_assert(alignof(ClassWithBuilder) == alignof(std::string));

void useClassRight() {
    ClassWithBuilder foo;
    foo.SetName("foo");
    foo.init();
    foo.doSomethingWhileRunning();
}

void useClassWrong1() {
    ClassWithBuilder foo;
    foo.SetName("foo");
    foo.init();
    // oops, can't set name after init
    foo.SetName("bar");
}

void useClassWrong2() {
    ClassWithBuilder foo;
    // oops, not running yet
    foo.doSomethingWhileRunning();
}

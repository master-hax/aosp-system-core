/*
 * Copyright 2020 The Android Open Source Project
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
#include <atomic>
#include <thread>

#include "fuzzer/FuzzedDataProvider.h"
#include "utils/RefBase.h"
#include "utils/StrongPointer.h"

using android::RefBase;
using android::sp;
using android::wp;

static constexpr int REFBASE_INITIAL_STRONG_VALUE = (1 << 28);
static constexpr int REFBASE_MAX_COUNT = 0xfffff;
static constexpr int MAX_OPERATIONS = 100;
static constexpr int MAX_THREADS = 10;
struct RefBaseSubclass : public RefBase {
    RefBaseSubclass() {}
    virtual ~RefBaseSubclass() {}
};

// A thread-specific state object for ref
struct RefThreadState {
    size_t strong_count = 0;
    size_t weak_count = 0;
};

RefBaseSubclass* ref;

bool canDecrementStrong(RefThreadState* state) {
    // BAD_STRONG decrements count by one. Since we want to avoid triggering it, we
    // subtract one.
    const int32_t count = state->strong_count - 1;
    // There's an assert around decrementing the strong count too much that causes
    // an artificial crash This is just running BAD_STRONG from RefBase
    return !(count <= 0 || ((count) & (~(REFBASE_MAX_COUNT | REFBASE_INITIAL_STRONG_VALUE))) != 0);
}

bool canDecrementWeak(RefThreadState* state) {
    // Same as BAD_STRONG, we subtract here to project ahead and avoid triggering BAD_WEAK
    const int32_t count = state->weak_count - 1;
    return !((count) <= 0 || ((count) & (~REFBASE_MAX_COUNT)) != 0);
}

std::vector<std::function<void(RefThreadState*)>> operations = {
        // Read-only operations
        [](RefThreadState*) -> void { ref->getStrongCount(); },
        [](RefThreadState*) -> void { ref->getWeakRefs()->getWeakCount(); },
        [](RefThreadState*) -> void { ref->printRefs(); },

        // Read/write operations
        [](RefThreadState* refState) -> void {
            ref->incStrong(nullptr);
            refState->strong_count++;
            refState->weak_count++;
        },
        [](RefThreadState* refState) -> void {
            // decStrong may also call decWeak internally
            if (canDecrementStrong(refState) && canDecrementWeak(refState)) {
                ref->decStrong(nullptr);
                refState->strong_count--;
                refState->weak_count--;
            }
        },
        [](RefThreadState* refState) -> void {
            ref->forceIncStrong(nullptr);
            refState->strong_count++;
            refState->weak_count++;
        },
        [](RefThreadState* refState) -> void {
            ref->createWeak(nullptr);
            refState->weak_count++;
        },
        [](RefThreadState* refState) -> void {
            // This will increment weak internally, then attempt to
            // promote it to strong. If it fails, it decrements weak.
            // If it succeeds, the weak is converted to strong.
            // Both cases net no weak reference change.
            if (ref->getWeakRefs()->attemptIncStrong(nullptr)) {
                refState->strong_count++;
            }
        },
        [](RefThreadState* refState) -> void {
            if (ref->getWeakRefs()->attemptIncWeak(nullptr)) {
                refState->weak_count++;
            }
        },
        [](RefThreadState* refState) -> void {
            if (canDecrementWeak(refState)) {
                ref->getWeakRefs()->decWeak(nullptr);
                refState->weak_count--;
            }
        },
        [](RefThreadState* refState) -> void {
            ref->getWeakRefs()->incWeak(nullptr);
            refState->weak_count++;
        },
};

void loop(const std::vector<uint8_t>& fuzzOps) {
    RefThreadState state;
    for (auto op : fuzzOps) {
        // If ref has deleted itself, we can no longer fuzz on this thread.
        if (ref == nullptr) {
            return;
        }
        operations[op % operations.size()](&state);
    }
    // Instead of explicitly freeing this, we're going to remove our weak and strong references.
    while (ref != nullptr && canDecrementStrong(&state) && canDecrementWeak(&state)) {
        ref->decStrong(nullptr);
        state.strong_count--;
        state.weak_count--;
    }
}

void spawnThreads(FuzzedDataProvider* dataProvider) {
    std::vector<std::thread> threads = std::vector<std::thread>();

    // Get the number of threads to generate
    uint8_t count = dataProvider->ConsumeIntegralInRange<uint8_t>(1, MAX_THREADS);
    // Generate threads
    for (uint8_t i = 0; i < count; i++) {
        uint8_t opCount = dataProvider->ConsumeIntegralInRange<uint8_t>(1, MAX_OPERATIONS);
        std::vector<uint8_t> threadOperations = dataProvider->ConsumeBytes<uint8_t>(opCount);
        std::thread tmp = std::thread(loop, threadOperations);
        threads.push_back(move(tmp));
    }

    for (auto& th : threads) {
        th.join();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ref = new RefBaseSubclass();
    FuzzedDataProvider dataProvider(data, size);
    spawnThreads(&dataProvider);
    return 0;
}

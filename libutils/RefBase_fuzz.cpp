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

#include <mutex>
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
  public:
    RefBaseSubclass(bool* deleted_check, std::mutex* deleted_mtx)
        : mDeleted(deleted_check), mMutex(deleted_mtx) {
        mMutex->lock();
        *mDeleted = false;
        mMutex->unlock();
    }

    virtual ~RefBaseSubclass() {
        mMutex->lock();
        *mDeleted = true;
        mMutex->unlock();
    }

  private:
    bool* mDeleted;
    std::mutex* mMutex;
};

// A thread-specific state object for ref
struct RefThreadState {
    size_t strong_count = 0;
    size_t weak_count = 0;
};

std::mutex deletedMutex;
bool refDeleted = false;
RefBaseSubclass* ref;

bool canDecrementStrong(RefThreadState* state) {
    // BAD_STRONG decrements count by one. Since we want to avoid triggering it,
    // we subtract one.
    const int32_t count = state->strong_count - 1;
    // There's an assert around decrementing the strong count too much that causes
    // an artificial crash This is just running BAD_STRONG from RefBase
    return !(count <= 0 || ((count) & (~(REFBASE_MAX_COUNT | REFBASE_INITIAL_STRONG_VALUE))) != 0);
}

bool canDecrementWeak(RefThreadState* state) {
    // Same as BAD_STRONG, we subtract here to project ahead and avoid triggering
    // BAD_WEAK
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
        },
        [](RefThreadState* refState) -> void {
            if (canDecrementStrong(refState)) {
                ref->decStrong(nullptr);
                refState->strong_count--;
            }
        },
        [](RefThreadState* refState) -> void {
            ref->forceIncStrong(nullptr);
            refState->strong_count++;
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
        deletedMutex.lock();
        if (refDeleted) {
            return;
        }
        deletedMutex.unlock();
        operations[op % operations.size()](&state);
    }

    // Instead of explicitly freeing this, we're going to remove our weak and
    // strong references.
    while (ref != nullptr && canDecrementStrong(&state)) {
        deletedMutex.lock();
        if (refDeleted) {
            break;
        }
        ref->decStrong(nullptr);
        deletedMutex.unlock();
        state.strong_count--;
    }
    // Clean up any remaining weak references
    while (ref != nullptr && canDecrementWeak(&state)) {
        deletedMutex.lock();
        if (refDeleted) {
            break;
        }
        ref->getWeakRefs()->decWeak(nullptr);
        deletedMutex.unlock();
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
    ref = new RefBaseSubclass(&refDeleted, &deletedMutex);
    FuzzedDataProvider dataProvider(data, size);
    spawnThreads(&dataProvider);

    // Lock not needed here, as all threads have been joined.
    if (!refDeleted) {
        // Since we are not modifying flags, (flags & OBJECT_LIFETIME_MASK) == OBJECT_LIFETIME_WEAK
        // should always be false. The destructor for RefBase is finnicky and will not clean up
        // weakref_impl properly because of this, To prevent memory leaks, we need to explicitly
        // delete ref->mRefs.
        RefBase::weakref_type* weakRefs = ref->getWeakRefs();
        delete ref;
        delete weakRefs;
    }
    return 0;
}

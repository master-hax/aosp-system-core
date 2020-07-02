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

bool canDecrementStrong(RefBase* ref) {
    // There's an assert around decrementing the strong count too much that causes an artifical
    // crash This is just running BAD_STRONG from RefBase
    const int32_t count = ref->getStrongCount() - 1;
    return !(count == 0 || ((count) & (~(REFBASE_MAX_COUNT | REFBASE_INITIAL_STRONG_VALUE))) != 0);
}
bool canDecrementWeak(RefBase* ref) {
    const int32_t count = ref->getWeakRefs()->getWeakCount() - 1;
    return !((count) == 0 || ((count) & (~REFBASE_MAX_COUNT)) != 0);
}

class RefBaseSubclass : public RefBase {
  public:
    explicit RefBaseSubclass(bool* deleted_check) : mDeleted(deleted_check) {
        *mDeleted = false;
        // These pointers to itself are mostly just to increase edge cases with
        // dependencies. May end up deleting them if they cause issues with the
        // fuzzer.
    }
    ~RefBaseSubclass() { *mDeleted = true; }

  private:
    bool* mDeleted;
};

void doNothing() {}
const void* doNothingPtr = reinterpret_cast<void*>(doNothing);
std::vector<std::function<void(RefBaseSubclass*)>> operations = {
        [](RefBaseSubclass* ref) -> void { ref->getStrongCount(); },
        [](RefBaseSubclass* ref) -> void { ref->printRefs(); },
        [](RefBaseSubclass* ref) -> void { ref->getWeakRefs()->printRefs(); },
        [](RefBaseSubclass* ref) -> void { ref->getWeakRefs()->getWeakCount(); },
        [](RefBaseSubclass* ref) -> void { ref->getWeakRefs()->refBase(); },
        [](RefBaseSubclass* ref) -> void { ref->incStrong(doNothingPtr); },
        [](RefBaseSubclass* ref) -> void {
            if (canDecrementStrong(ref)) {
                ref->decStrong(doNothingPtr);
            }
        },
        [](RefBaseSubclass* ref) -> void { ref->forceIncStrong(doNothingPtr); },
        [](RefBaseSubclass* ref) -> void { ref->createWeak(doNothingPtr); },
        [](RefBaseSubclass* ref) -> void { ref->getWeakRefs()->attemptIncStrong(doNothingPtr); },
        [](RefBaseSubclass* ref) -> void { ref->getWeakRefs()->attemptIncWeak(doNothingPtr); },
        [](RefBaseSubclass* ref) -> void {
            if (canDecrementWeak(ref)) {
                ref->getWeakRefs()->decWeak(doNothingPtr);
            }
        },
        [](RefBaseSubclass* ref) -> void { ref->getWeakRefs()->incWeak(doNothingPtr); },
        [](RefBaseSubclass* ref) -> void { ref->getWeakRefs()->printRefs(); },
};

void loop(RefBaseSubclass* loopRef, std::vector<uint8_t> fuzzOps) {
    for (auto& op : fuzzOps) {
        operations[op % operations.size()](loopRef);
    }
}

void spawnThreads(FuzzedDataProvider* dataProvider) {
    bool val = false;
    std::vector<std::thread> threads = std::vector<std::thread>();

    // Get the number of threads to generate
    uint8_t count = dataProvider->ConsumeIntegralInRange<uint8_t>(1, MAX_THREADS);

    // Generate threads
    for (uint8_t i = 0; i < count; i++) {
        RefBaseSubclass* threadRef = new RefBaseSubclass(&val);
        uint8_t opCount = dataProvider->ConsumeIntegralInRange<uint8_t>(1, MAX_OPERATIONS);
        std::vector<uint8_t> threadOperations = dataProvider->ConsumeBytes<uint8_t>(opCount);
        ;
        std::thread tmp = std::thread(loop, threadRef, threadOperations);
        threads.push_back(move(tmp));
    }

    for (auto& th : threads) {
        if (th.joinable()) {
            th.join();
        }
    }
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider dataProvider(data, size);
    spawnThreads(&dataProvider);
    return 0;
}

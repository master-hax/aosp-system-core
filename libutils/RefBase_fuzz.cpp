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
    RefBaseSubclass() {}
    virtual ~RefBaseSubclass() {}
};
sp<RefBaseSubclass> ref;
std::mutex refAccess;

bool canDecrementStrong() {
    // BAD_STRONG decrements count by one. Since we want to avoid triggering it, we
    // subtract one.
    const int32_t count = ref->getStrongCount() - 1;
    // There's an assert around decrementing the strong count too much that causes
    // an artificial crash This is just running BAD_STRONG from RefBase
    return !(count == 0 || ((count) & (~(REFBASE_MAX_COUNT | REFBASE_INITIAL_STRONG_VALUE))) != 0);
}
bool canDecrementWeak() {
    // Same as BAD_STRONG, we subtract here to project ahead and avoid triggering BAD_WEAK
    const int32_t count = ref->getWeakRefs()->getWeakCount() - 1;
    return !((count) == 0 || ((count) & (~REFBASE_MAX_COUNT)) != 0);
}

std::vector<std::function<void()>> operations = {
        []() -> void {
            refAccess.lock();
            ref->getStrongCount();
            refAccess.unlock();
        },
        []() -> void { ref->printRefs(); },
        []() -> void {
            refAccess.lock();
            ref->getWeakRefs()->getWeakCount();
            refAccess.unlock();
        },
        []() -> void {
            refAccess.lock();
            ref->incStrong(nullptr);
            refAccess.unlock();
        },
        []() -> void {
            refAccess.lock();
            // decStrong may also call decWeak internally
            if (canDecrementStrong() && canDecrementWeak()) {
                ref->decStrong(nullptr);
            }
            refAccess.unlock();
        },
        []() -> void {
            refAccess.lock();
            // forceIncStrong will call decWeak in some cases
            if (canDecrementWeak()) {
                ref->forceIncStrong(nullptr);
            }
            refAccess.unlock();
        },
        []() -> void {
            refAccess.lock();
            ref->createWeak(nullptr);
            refAccess.unlock();
        },
        []() -> void {
            refAccess.lock();
            ref->getWeakRefs()->attemptIncStrong(nullptr);
            refAccess.unlock();
        },
        []() -> void {
            refAccess.lock();
            ref->getWeakRefs()->attemptIncWeak(nullptr);
            refAccess.unlock();
        },
        []() -> void {
            refAccess.lock();
            if (canDecrementWeak()) {
                ref->getWeakRefs()->decWeak(nullptr);
            }
            refAccess.unlock();
        },
        []() -> void {
            refAccess.lock();
            ref->getWeakRefs()->incWeak(nullptr);
            refAccess.unlock();
        },
        []() -> void { ref->getWeakRefs()->printRefs(); },
};
void loop(const std::vector<uint8_t>& fuzzOps) {
    for (auto op : fuzzOps) {
        operations[op % operations.size()]();
    }
}
void spawnThreads(FuzzedDataProvider* dataProvider) {
    std::vector<std::thread> threads = std::vector<std::thread>();
    ;
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
    ref = sp<RefBaseSubclass>::make();
    FuzzedDataProvider dataProvider(data, size);
    spawnThreads(&dataProvider);
    // Instead of explicitly freeing this, we're going to remove all weak and strong references.
    while (ref != nullptr && canDecrementWeak() && canDecrementStrong()) {
        ref->decStrong(nullptr);
    }
    return 0;
}

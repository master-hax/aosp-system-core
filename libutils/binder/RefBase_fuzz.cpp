/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <fuzzer/FuzzedDataProvider.h>
#include "utils/RefBase.h"

using namespace android;
using android::RefBase;

static constexpr int32_t kMinRefCount = 1;

class RefBaseSubclass : public RefBase {
  public:
    RefBaseSubclass(bool* deleted_check) : mDeleted(deleted_check) {
        extendObjectLifetime(OBJECT_LIFETIME_WEAK);
    }

    ~RefBaseSubclass() { *mDeleted = true; }

  private:
    bool* mDeleted;
};

static void process(FuzzedDataProvider& fdp) {
    bool isDeleted = false;
    sp<RefBaseSubclass> ref = new RefBaseSubclass(&isDeleted);
    RefBase::weakref_type* weakRefs = ref->getWeakRefs();
    int32_t id = fdp.ConsumeIntegral<int32_t>();
    int32_t strongCount = ref->getStrongCount();
    int32_t weakCount = weakRefs->getWeakCount();
    while (fdp.remaining_bytes()) {
        if (isDeleted) {
            break;
        }
        auto invokeRefbaseAPI = fdp.PickValueInArray<const std::function<void()>>({
                [&]() { ref->printRefs(); },
                [&]() {
                    ref->incStrong((void*)&id);
                    ++strongCount;
                },
                [&]() {
                    ref->forceIncStrong((void*)&id);
                    ++strongCount;
                },
                [&]() {
                    ref->createWeak((void*)&id);
                    ++weakCount;
                },
                [&]() {
                    if (weakRefs->attemptIncStrong((void*)&id)) {
                        ++strongCount;
                    }
                },
                [&]() {
                    if (weakRefs->attemptIncWeak((void*)&id)) {
                        ++weakCount;
                    }
                },
                [&]() {
                    weakRefs->incWeak((void*)&id);
                    ++weakCount;
                },
                [&]() {
                    if (strongCount > kMinRefCount) {
                        ref->decStrong((void*)&id);
                        --strongCount;
                    }
                },
                [&]() {
                    if (weakCount > kMinRefCount) {
                        weakRefs->decWeak((void*)&id);
                        --weakCount;
                    }
                },
                [&]() {
                    ref->incStrongRequireStrong((void*)&id);
                    ++strongCount;
                },
                [&]() {
                    weakRefs->incWeakRequireWeak((void*)&id);
                    ++weakCount;
                },
                [&]() { weakRefs->trackMe(fdp.ConsumeBool(), fdp.ConsumeBool()); },
        });
        invokeRefbaseAPI();
    }

    // Remove all weak and strong references.
    if (!isDeleted && weakCount > kMinRefCount) {
        for (; weakCount > kMinRefCount; weakCount--) {
            weakRefs->decWeak((void*)&id);
        }
    }
    if (!isDeleted && strongCount > kMinRefCount) {
        for (; strongCount > kMinRefCount; strongCount--) {
            ref->decStrong((void*)&id);
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    process(fdp);
    return 0;
}

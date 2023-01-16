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

static constexpr int32_t kMaxAPIS = 13;

class RefBaseSubclass : public RefBase {
  public:
    RefBaseSubclass() { extendObjectLifetime(OBJECT_LIFETIME_WEAK); }
};

class RefBaseFuzzer {
  public:
    RefBaseFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

  private:
    FuzzedDataProvider mFdp;
};

void RefBaseFuzzer::process() {
    int32_t strongCount = 0;
    int32_t weakCount = 0;
    sp<RefBaseSubclass> ref = new RefBaseSubclass();
    RefBase::weakref_type* weakRefs = ref->getWeakRefs();
    int32_t id = mFdp.ConsumeIntegral<int32_t>();
    while (mFdp.remaining_bytes()) {
        int32_t refbaseFunc = mFdp.ConsumeIntegralInRange(0, kMaxAPIS);
        switch (refbaseFunc) {
            case 0:
                ref->getStrongCount();
                break;
            case 1:
                weakRefs->getWeakCount();
                break;
            case 2:
                ref->printRefs();
                break;
            case 3:
                ref->incStrong((void*)&id);
                ++strongCount;
                break;
            case 4:
                ref->forceIncStrong((void*)&id);
                ++strongCount;
                break;
            case 5:
                ref->createWeak((void*)&id);
                ++weakCount;
                break;
            case 6:
                if (weakRefs->attemptIncStrong((void*)&id)) {
                    ++strongCount;
                }
                break;
            case 7:
                if (weakRefs->attemptIncWeak((void*)&id)) {
                    ++weakCount;
                }
                break;
            case 8:
                weakRefs->incWeak((void*)&id);
                ++weakCount;
                break;
            case 9:
                if (strongCount > 0) {
                    ref->decStrong((void*)&id);
                    --strongCount;
                }
                break;
            case 10:
                if (weakCount > 0) {
                    weakRefs->decWeak((void*)&id);
                    --weakCount;
                }
                break;
            case 11:
                ref->incStrongRequireStrong((void*)&id);
                ++strongCount;
                break;
            case 12:
                weakRefs->incWeakRequireWeak((void*)&id);
                ++weakCount;
                break;
            case 13:
                weakRefs->trackMe(mFdp.ConsumeBool(), mFdp.ConsumeBool());
                break;
        }
    }

    // Remove all weak and strong references.
    if (weakCount > 0) {
        for (; weakCount > 0; weakCount--) {
            weakRefs->decWeak((void*)&id);
        }
    }
    if (strongCount > 0) {
        for (; strongCount > 0; strongCount--) {
            ref->decStrong((void*)&id);
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    RefBaseFuzzer refBaseFuzzer(data, size);
    refBaseFuzzer.process();
    return 0;
}

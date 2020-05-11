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

#include "fuzzer/FuzzedDataProvider.h"
#include "utils/BitSet.h"

template <typename T>
void runOperationForBit(T bs, uint32_t bit, uint8_t operation) {
    switch (operation) {
        case 0:
            bs.markBit(bit);
            break;
        case 1:
            bs.valueForBit(bit);
            break;
        case 2:
            bs.hasBit(bit);
            break;
        case 3:
            bs.clearBit(bit);
            break;
        case 4:
            bs.clearFirstMarkedBit();
            break;
        case 5:
            bs.clear();
            break;
        case 6:
            bs.count();
            break;
        case 7:
            bs.isEmpty();
            break;
        case 8:
            bs.isFull();
            break;
        case 9:
            bs.firstMarkedBit();
            break;
        case 10:
            bs.lastMarkedBit();
            break;
        case 11:
            bs.clearFirstMarkedBit();
            break;
        case 12:
            bs.markFirstUnmarkedBit();
            break;
        case 13:
            bs.clearLastMarkedBit();
            break;
        case 14:
            bs.getIndexOfBit(bit);
            break;
    }
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    FuzzedDataProvider dataProvider(Data, Size);
    uint32_t thirty_two_base = dataProvider.ConsumeIntegral<uint32_t>();
    uint64_t sixty_four_base = dataProvider.ConsumeIntegral<uint64_t>();
    android::BitSet32 b1 = android::BitSet32(thirty_two_base);
    android::BitSet64 b2 = android::BitSet64(sixty_four_base);
    for (size_t i = 0; i < dataProvider.remaining_bytes(); i++) {
        uint32_t bit = dataProvider.ConsumeIntegral<uint32_t>();
        uint8_t op = dataProvider.ConsumeIntegralInRange<uint8_t>(0, 14);
        runOperationForBit<android::BitSet32>(b1, bit, op);
        runOperationForBit<android::BitSet64>(b2, bit, op);
    }
    return 0;
}

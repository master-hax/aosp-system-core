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

#include <utils/String16.h>

#include <iostream>

#include "fuzzer/FuzzedDataProvider.h"

#define MAX_BYTES 32

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    FuzzedDataProvider dataProvider(Data, Size);

    // We're generating two char vectors.
    // First, generate lengths.
    const size_t kVecOneLen = dataProvider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES);
    const size_t kVecTwoLen = dataProvider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES);
    // We need at least enough bytes to fill these vectors
    if (dataProvider.remaining_bytes() < (kVecOneLen + kVecTwoLen) * sizeof(char16_t)) {
        return 0;
    }

    // Next, populate the vectors
    std::vector<char> vec = dataProvider.ConsumeBytesWithTerminator<char>(kVecOneLen);
    std::vector<char> vec_two = dataProvider.ConsumeBytesWithTerminator<char>(kVecTwoLen);

    // Get pointers to their data
    char* str = vec.data();
    char* str_two = vec_two.data();

    // Create UTF16 representations
    android::String16 str_one_utf16 = android::String16(str);
    android::String16 str_two_utf16 = android::String16(str_two);
    // This will be where most of our changes are applied
    android::String16 str_one_appended_utf16 = android::String16(str, vec.size());
    str_one_appended_utf16.append(str_two_utf16);

    // Insert operation
    int pos = dataProvider.ConsumeIntegralInRange<int>(0, str_one_utf16.size());
    str_one_appended_utf16.insert(pos, str_one_utf16.string());
    // Find/contains operations
    char16_t searchChar = dataProvider.ConsumeIntegral<char16_t>();
    str_one_appended_utf16.findFirst(searchChar);
    str_one_appended_utf16.findLast(searchChar);
    str_one_appended_utf16.startsWith(str_one_utf16);
    str_one_appended_utf16.contains(str_one_utf16.string());
    str_one_appended_utf16.isStaticString();
    // Replace/remove operations
    char16_t replaceChar = dataProvider.ConsumeIntegral<char16_t>();
    str_one_appended_utf16.replaceAll(searchChar, replaceChar);
    size_t len = dataProvider.ConsumeIntegral<size_t>();
    size_t begin = dataProvider.ConsumeIntegral<size_t>();
    str_one_appended_utf16.remove(len, begin);

    // Comparison to both strings
    str_one_appended_utf16.compare(str_one_utf16);
    str_one_appended_utf16.compare(str_two_utf16);
    str_one_appended_utf16.size();
    // Interestingly, utf16 strings don't have a makeUpper operation
    str_one_appended_utf16.makeLower();
    // Just to be extra sure these can be freed, we're going to clear them out.
    str_one_utf16.remove(0, str_one_utf16.size());
    str_one_appended_utf16.remove(0, str_one_appended_utf16.size());
    str_two_utf16.remove(0, str_two_utf16.size());
    return 0;
}

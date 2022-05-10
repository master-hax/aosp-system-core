/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "unicode"

#include <utils/Unicode.h>

#include <smmintrin.h>

extern "C" {

#if defined(__SSE4_2__)

size_t strlen16(const char16_t* s) {
    for (const char16_t* ss = s;; ss += 8) {
        constexpr uint8_t kMode = _SIDD_UWORD_OPS | _SIDD_CMP_EQUAL_EACH | _SIDD_LEAST_SIGNIFICANT;
        // This returns the index (from 0 to 7) of the first character whose value
        // is 0, or 8 if not found.
        int r = _mm_cmpistri(_mm_setzero_si128(),
                             _mm_loadu_si128(reinterpret_cast<const __m128i*>(ss)), kMode);
        if (r != 8) return (ss - s) + r;
    }
}

size_t strnlen16(const char16_t* s, size_t maxlen) {
    constexpr uint8_t kMode = _SIDD_UWORD_OPS | _SIDD_CMP_EQUAL_EACH | _SIDD_LEAST_SIGNIFICANT;
    const char16_t* ss = s;
    for (; maxlen >= 8; ss += 8, maxlen -= 8) {
        // This returns the index (from 0 to 7) of the first character whose value
        // is 0, or 8 if not found.
        int r = _mm_cmpistri(_mm_setzero_si128(),
                             _mm_loadu_si128(reinterpret_cast<const __m128i*>(ss)), kMode);
        if (r != 8) return (ss - s) + r;
    }
    if (maxlen == 0) return ss - s;

    // This returns the index of the first character whose value is 0, or maxlen
    // if not found.
    int r = _mm_cmpestri(_mm_setzero_si128(), maxlen,
                         _mm_loadu_si128(reinterpret_cast<const __m128i*>(ss)), maxlen, kMode);
    return (ss - s) + r;
}

#endif  // defined(__SSE4_2__)

}  // extern "C"

/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
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

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace crypto {

template<size_t N>
class Counter {
public:
    void increase() {
        for (size_t i = sizeof(counter) - 1; i < sizeof(counter); --i) {
            if (++counter[i] != 0) {
                break;
            }
        }
    }

    uint8_t* data() { return counter; }
    const uint8_t* data() const { return counter; }

    constexpr size_t size() const { return sizeof(counter); }

    uint8_t& operator[](size_t index) { return counter[index]; }
    const uint8_t& operator[](size_t index) const { return counter[index]; }
private:
    uint8_t counter[N];
};

}  // namespace


#pragma once

/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <stdint.h>

#include <chrono>

enum class BenchmarkCommand: uint8_t {
    EXIT,
    READ, // followed by a uint32_t length, followed by length bytes
    WRITE, // followed by uint32_t length, responded to by length bytes
};

// TODO: Use a tagged union.

#define TRANSFER_LENGTH 16384

struct Timer {
    using Clock = std::chrono::high_resolution_clock;
    using time_point = Clock::time_point;
    using duration = Clock::duration;

    time_point start_time;

    Timer() {
        start();
    }

    void start() {
        start_time = Clock::now();
    }

    duration end() {
        return Clock::now() - start_time;
    }
};



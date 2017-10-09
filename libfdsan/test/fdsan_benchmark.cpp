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

#include <benchmark/benchmark.h>

#include "fdsan_backtrace.h"

static void BM_fdsan_record(benchmark::State& state) {
  while (state.KeepRunning()) {
    FdsanBacktrace* backtrace = fdsan_record_backtrace();
    fdsan_free(backtrace);
  }
}

BENCHMARK(BM_fdsan_record)->Threads(1)->Threads(32)->Threads(128);
BENCHMARK_MAIN();

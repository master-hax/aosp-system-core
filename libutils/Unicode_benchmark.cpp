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

#include <benchmark/benchmark.h>
#include <utils/Unicode.h>

static void BM_strlen16(benchmark::State& state) {
    const size_t n = state.range(0);
    std::vector<char16_t> buf(n, u'x');
    buf[n - 1] = 0;
    while (state.KeepRunning()) {
        benchmark::DoNotOptimize(strlen16(buf.data()));
    }
    state.SetBytesProcessed(state.iterations() * n * sizeof(char16_t));
}
BENCHMARK(BM_strlen16)->Arg(8)->Arg(16)->Arg(32)->Arg(64)->Arg(128);

static void BM_strnlen16(benchmark::State& state) {
    const size_t n = state.range(0);
    std::vector<char16_t> buf(n, u'x');
    while (state.KeepRunning()) {
        benchmark::DoNotOptimize(strnlen16(buf.data(), n));
    }
    state.SetBytesProcessed(state.iterations() * n * sizeof(char16_t));
}
BENCHMARK(BM_strnlen16)->Arg(8)->Arg(16)->Arg(32)->Arg(64)->Arg(128);

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

#include "subcontext.h"

#include <benchmark/benchmark.h>

#include "test_function_map.h"

namespace android {
namespace init {

static void BenchmarkSuccess(benchmark::State& state) {
    TestFunctionMap test_function_map;
    test_function_map.Add("return_success", 0, 0, true,
                          [](const std::vector<std::string>& args) { return Success(); });

    subcontext_function_map = &test_function_map;

    auto subcontext = Subcontext("path", "u:object_r:init:s0");

    while (state.KeepRunning()) {
        subcontext.Execute(std::vector<std::string>{"return_success"});
    }
}

BENCHMARK(BenchmarkSuccess);

}  // namespace init
}  // namespace android

BENCHMARK_MAIN()

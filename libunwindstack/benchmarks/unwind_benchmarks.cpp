/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <memory>
#include <regex>

#include <benchmark/benchmark.h>

#include <android-base/strings.h>

#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>
#include <unwindstack/RegsGetLocal.h>
#include <unwindstack/Unwinder.h>

size_t Call6(std::shared_ptr<unwindstack::Memory>& process_memory, unwindstack::Maps* maps) {
  std::unique_ptr<unwindstack::Regs> regs(unwindstack::Regs::CreateFromLocal());
  unwindstack::RegsGetLocal(regs.get());
  unwindstack::Unwinder unwinder(32, maps, regs.get(), process_memory);
  unwinder.Unwind();
  return unwinder.NumFrames();
}

size_t Call5(std::shared_ptr<unwindstack::Memory>& process_memory, unwindstack::Maps* maps) {
  return Call6(process_memory, maps);
}

size_t Call4(std::shared_ptr<unwindstack::Memory>& process_memory, unwindstack::Maps* maps) {
  return Call5(process_memory, maps);
}

size_t Call3(std::shared_ptr<unwindstack::Memory>& process_memory, unwindstack::Maps* maps) {
  return Call4(process_memory, maps);
}

size_t Call2(std::shared_ptr<unwindstack::Memory>& process_memory, unwindstack::Maps* maps) {
  return Call3(process_memory, maps);
}

size_t Call1(std::shared_ptr<unwindstack::Memory>& process_memory, unwindstack::Maps* maps) {
  return Call2(process_memory, maps);
}

static void BM_uncached_unwind(benchmark::State& state) {
  auto process_memory = unwindstack::Memory::CreateProcessMemory(getpid());
  unwindstack::LocalMaps maps;
  if (!maps.Parse()) {
    state.SkipWithError("Failed to parse local maps.");
  }

  for (auto _ : state) {
    benchmark::DoNotOptimize(Call1(process_memory, &maps));
  }
}
BENCHMARK(BM_uncached_unwind);

static void BM_cached_unwind(benchmark::State& state) {
  auto process_memory = unwindstack::Memory::CreateProcessMemoryCached(getpid());
  unwindstack::LocalMaps maps;
  if (!maps.Parse()) {
    state.SkipWithError("Failed to parse local maps.");
  }

  for (auto _ : state) {
    benchmark::DoNotOptimize(Call1(process_memory, &maps));
  }
}
BENCHMARK(BM_cached_unwind);

static void Initialize(benchmark::State& state, unwindstack::Maps& maps,
                       unwindstack::MapInfo** libc_map_info) {
  if (!maps.Parse()) {
    state.SkipWithError("Failed to parse local maps.");
    return;
  }

#if !defined(__ANDROID__)
  std::regex re("/libc.*\\.so$");
#endif

  // Find the libc.so share library and use that for benchmark purposes.
  *libc_map_info = nullptr;
  for (unwindstack::MapInfo* map_info : maps) {
#if defined(__ANDROID__)
    if (map_info->offset == 0 && android::base::EndsWith(map_info->name, "/libc.so")) {
      *libc_map_info = map_info;
      break;
    }
#else
    if (map_info->offset == 0 && std::regex_search(map_info->name, re)) {
      *libc_map_info = map_info;
      break;
    }
#endif
  }

  if (*libc_map_info == nullptr) {
    state.SkipWithError("Failed to find libc.so shared library map.");
  }
}

static void BM_get_build_id_uncached(benchmark::State& state) {
  unwindstack::LocalMaps maps;
  unwindstack::MapInfo* libc_map_info;
  Initialize(state, maps, &libc_map_info);

  auto process_memory = unwindstack::Memory::CreateProcessMemory(getpid());
  for (auto _ : state) {
    uintptr_t id = libc_map_info->build_id;
    if (id != 0) {
      delete reinterpret_cast<std::string*>(id);
      libc_map_info->build_id = 0;
    }
    benchmark::DoNotOptimize(libc_map_info->GetBuildID(process_memory));
  }
}
BENCHMARK(BM_get_build_id_uncached);

static void BM_get_build_id_cached(benchmark::State& state) {
  unwindstack::LocalMaps maps;
  unwindstack::MapInfo* libc_map_info;
  Initialize(state, maps, &libc_map_info);

  auto process_memory = unwindstack::Memory::CreateProcessMemoryCached(getpid());
  for (auto _ : state) {
    uintptr_t id = libc_map_info->build_id;
    if (id != 0) {
      delete reinterpret_cast<std::string*>(id);
      libc_map_info->build_id = 0;
    }
    benchmark::DoNotOptimize(libc_map_info->GetBuildID(process_memory));
  }
}
BENCHMARK(BM_get_build_id_cached);

BENCHMARK_MAIN();

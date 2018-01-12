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

#include <ctype.h>
#include <link.h>
#include <linux/elf.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <unistd.h>

#include <string>
#include <unordered_map>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <gtest/gtest.h>
#include <private/android_filesystem_config.h>

#define INCLUDED_IN_GTEST
#include "liblog_benchmark.cpp"

using namespace android::base;

// anonymous namespace houses all the local helper functions

namespace {

constexpr char info[] = "[ INFO     ] ";
constexpr char warning[] = "[ WARNING  ] ";

// mostly borrowed from bionic/lbic/bionic/vdso.cpp
bool getVdsoSymbol(const char* symbol) {
  static std::unordered_map<std::string, bool> found;

  auto it = found.find(symbol);
  if (it != found.end()) {
    return it->second;
  }

  uintptr_t vdso_ehdr_addr = getauxval(AT_SYSINFO_EHDR);
  ElfW(Ehdr)* vdso_ehdr = reinterpret_cast<ElfW(Ehdr)*>(vdso_ehdr_addr);
  if (vdso_ehdr == nullptr) {
    std::cerr << warning << "AT_SYSINFO_EHDR not found\n";
    found.emplace(std::make_pair(std::string(symbol), false));
    return false;
  }

  // How many symbols does it have?
  size_t symbol_count = 0;
  ElfW(Shdr)* vdso_shdr =
      reinterpret_cast<ElfW(Shdr)*>(vdso_ehdr_addr + vdso_ehdr->e_shoff);
  for (size_t i = 0; i < vdso_ehdr->e_shnum; ++i) {
    if (vdso_shdr[i].sh_type == SHT_DYNSYM) {
      symbol_count = vdso_shdr[i].sh_size / sizeof(ElfW(Sym));
    }
  }
  if (symbol_count == 0) {
    std::cerr << warning << "AT_SYSINFO_EHDR has no symbols\n";
    found.emplace(std::make_pair(std::string(symbol), false));
    return false;
  }

  // Where's the dynamic table?
  ElfW(Addr) vdso_addr = 0;
  ElfW(Dyn)* vdso_dyn = nullptr;
  ElfW(Phdr)* vdso_phdr =
      reinterpret_cast<ElfW(Phdr)*>(vdso_ehdr_addr + vdso_ehdr->e_phoff);
  for (size_t i = 0; i < vdso_ehdr->e_phnum; ++i) {
    if (vdso_phdr[i].p_type == PT_DYNAMIC) {
      vdso_dyn =
          reinterpret_cast<ElfW(Dyn)*>(vdso_ehdr_addr + vdso_phdr[i].p_offset);
    } else if (vdso_phdr[i].p_type == PT_LOAD) {
      vdso_addr = vdso_ehdr_addr + vdso_phdr[i].p_offset - vdso_phdr[i].p_vaddr;
    }
  }
  if (vdso_addr == 0 || vdso_dyn == nullptr) {
    std::cerr << warning << "no vdso page\n";
    found.emplace(std::make_pair(std::string(symbol), false));
    return false;
  }

  // Where are the string and symbol tables?
  const char* strtab = nullptr;
  ElfW(Sym)* symtab = nullptr;
  for (ElfW(Dyn)* d = vdso_dyn; d->d_tag != DT_NULL; ++d) {
    if (d->d_tag == DT_STRTAB) {
      strtab = reinterpret_cast<const char*>(vdso_addr + d->d_un.d_ptr);
    } else if (d->d_tag == DT_SYMTAB) {
      symtab = reinterpret_cast<ElfW(Sym)*>(vdso_addr + d->d_un.d_ptr);
    }
  }
  if (strtab == nullptr || symtab == nullptr) {
    std::cerr << warning << "no vdso symtab\n";
    found.emplace(std::make_pair(std::string(symbol), false));
    return false;
  }

  // Are there any symbols we want?
  for (size_t i = 0; i < symbol_count; ++i) {
    if (((std::string("__kernel_") + symbol) == (strtab + symtab[i].st_name)) ||
        ((std::string("__vdso_") + symbol) == (strtab + symtab[i].st_name))) {
      std::cerr << info << (strtab + symtab[i].st_name) << "=" << std::hex
                << (vdso_addr + symtab[i].st_value) << "\n";
      found.emplace(std::make_pair(std::string(symbol), true));
      return true;
    }
  }
  std::cerr << warning << symbol << " not found in vdso\n";
  found.emplace(std::make_pair(std::string(symbol), false));
  return false;
}

// More consistent measurement/benchmarking result if we
// do not hop from cpu to cpu to perform the iterations.
void setAffinityCurrent() {
#ifdef _SC_NPROCESSORS_CONF
  auto numCpus = sysconf(_SC_NPROCESSORS_CONF);
#else
  auto numCpus = 32;
#endif
  auto cpu = sched_getcpu();
  EXPECT_LE(0, cpu) << "errno=" << errno;
  if (cpu >= numCpus) {
    numCpus = cpu + 1;
  }
  cpu_set_t* cpus = CPU_ALLOC(numCpus);
  CPU_ZERO(cpus);
  CPU_SET(cpu, cpus);
  pid_t tid = gettid();
  EXPECT_EQ(0, sched_setaffinity(tid, CPU_ALLOC_SIZE(numCpus), cpus))
      << "CPU" << cpu << " tid=" << tid << " errno=" << errno;
  CPU_FREE(cpus);
  std::cerr << info << "affinity locked to CPU" << cpu << "\n";
}

void releaseAffinityCurrent() {
#ifdef _SC_NPROCESSORS_CONF
  auto numCpus = sysconf(_SC_NPROCESSORS_CONF);
#else
  auto numCpus = 32;
#endif
  auto cpu = sched_getcpu();
  EXPECT_LE(0, cpu) << "errno=" << errno;
  if (cpu >= numCpus) {
    numCpus = cpu + 1;
  }
  cpu_set_t* cpus = CPU_ALLOC(numCpus);
  CPU_ZERO(cpus);
  for (cpu = 0; cpu < numCpus; ++cpu) {
    CPU_SET(cpu, cpus);
  }
  pid_t tid = gettid();
  EXPECT_EQ(0, sched_setaffinity(tid, CPU_ALLOC_SIZE(numCpus), cpus))
      << "tid=" << tid << " errno=" << errno;
  CPU_FREE(cpus);
  std::cerr << info << "affinity released\n";
}

std::string benchmarks;

constexpr char benchmarkMissing[] = "<MISSING>";

void getBenchmarks() {
  if (benchmarks.length()) return;

  char* argv[] = {
    // clang-format off
    const_cast<char*>("liblog-benchmarks"),
    const_cast<char*>("--benchmark_color=false"),
    const_cast<char*>("--benchmark_filter=BM_time*"),
    nullptr,
    // clang-format on
  };
  int argc = arraysize(argv) - 1;
  benchmark::Initialize(&argc, argv);
  if (benchmark::ReportUnrecognizedArguments(argc, argv)) {
    benchmarks = benchmarkMissing;
    return;
  }
  std::ostringstream out;
  benchmark::ConsoleReporter output(benchmark::ConsoleReporter::OO_Tabular);
  output.SetOutputStream(&out);
  output.SetErrorStream(&out);

  setAffinityCurrent();
  benchmark::RunSpecifiedBenchmarks(&output);
  std::string str = out.str();
  while (str.length() && (str[str.length() - 1] == '\n')) {
    str.erase(str.length() - 1);
  }
  if (str.length()) {
    std::cerr << info << "Benchmark results:\n";
    std::cerr << str << '\n';
  }
  releaseAffinityCurrent();

  if (!str.length()) str = benchmarkMissing;
  benchmarks = str;
}

bool benchmarkAccess() {
  getBenchmarks();
  return benchmarks != benchmarkMissing;
}

constexpr size_t npos = std::string::npos;

int64_t getBenchmark(const std::string& bench) {
  getBenchmarks();

  size_t pos = 0;
  do {
    pos = benchmarks.find("\n" + bench, pos);
    if (pos == npos) return -1;
    pos += bench.length() + 1;
  } while (!isblank(benchmarks[pos]));

  do {
    ++pos;
    if (pos >= benchmarks.length()) return -1;
  } while (isblank(benchmarks[pos]));
  if (!isdigit(benchmarks[pos])) return -1;

  size_t end = benchmarks.find('\n', pos);
  if (end != npos) end -= pos;

  auto result = std::stoull(benchmarks.substr(pos, end));
  if (result > INT64_MAX) {
    result = INT64_MAX;
  }
  return result;
}

// Cache results

int64_t getBenchmark_BM_time_clock_gettime_syscall() {
  static int64_t gettime_period;

  if (gettime_period) return gettime_period;
  gettime_period = getBenchmark("BM_time_clock_gettime_MONOTONIC_syscall");
  return gettime_period;
}

int64_t getBenchmark_BM_time_clock_gettime_MONOTONIC() {
  static int64_t gettime_period;

  if (gettime_period) return gettime_period;
  gettime_period = getBenchmark("BM_time_clock_gettime_MONOTONIC");
  return gettime_period;
}

int64_t getBenchmark_BM_time_clock_gettime_REALTIME() {
  static int64_t gettime_period;

  if (gettime_period) return gettime_period;
  gettime_period = getBenchmark("BM_time_clock_gettime_REALTIME");
  return gettime_period;
}

int64_t getBenchmark_BM_time_clock_gettime_BOOTTIME() {
  static int64_t gettime_period;

  if (gettime_period) return gettime_period;
  gettime_period = getBenchmark("BM_time_clock_gettime_BOOTTIME");
  return gettime_period;
}

int64_t getBenchmark_BM_time_clock_gettime_MONOTONIC_RAW() {
  static int64_t gettime_period;

  if (gettime_period) return gettime_period;
  gettime_period = getBenchmark("BM_time_clock_gettime_MONOTONIC_RAW");
  return gettime_period;
}

}  // namespace

TEST(liblog, time_clock_gettime_MONOTONIC_is_vdso) {
  ASSERT_TRUE(getVdsoSymbol("clock_gettime"));
  ASSERT_TRUE(benchmarkAccess());

  ASSERT_GT(getBenchmark_BM_time_clock_gettime_syscall(), 0);
  ASSERT_GT(getBenchmark_BM_time_clock_gettime_MONOTONIC(), 0);
  ASSERT_GT(getBenchmark_BM_time_clock_gettime_syscall(),
            getBenchmark_BM_time_clock_gettime_MONOTONIC() * 2);
}

TEST(liblog, time_clock_gettime_REALTIME_is_vdso) {
  ASSERT_TRUE(getVdsoSymbol("clock_gettime"));
  ASSERT_TRUE(benchmarkAccess());

  ASSERT_GT(getBenchmark_BM_time_clock_gettime_syscall(), 0);
  ASSERT_GT(getBenchmark_BM_time_clock_gettime_REALTIME(), 0);
  ASSERT_GT(getBenchmark_BM_time_clock_gettime_syscall(),
            getBenchmark_BM_time_clock_gettime_REALTIME() * 2);
}

TEST(liblog, time_clock_gettime_BOOTTIME_is_vdso) {
  ASSERT_TRUE(getVdsoSymbol("clock_gettime"));
  ASSERT_TRUE(benchmarkAccess());

  ASSERT_GT(getBenchmark_BM_time_clock_gettime_syscall(), 0);
  ASSERT_GT(getBenchmark_BM_time_clock_gettime_BOOTTIME(), 0);
  ASSERT_GT(getBenchmark_BM_time_clock_gettime_syscall(),
            getBenchmark_BM_time_clock_gettime_BOOTTIME() * 2);
}

TEST(liblog, time_clock_gettime_MONOTONIC_RAW_is_vdso) {
  ASSERT_TRUE(getVdsoSymbol("clock_gettime"));
  ASSERT_TRUE(benchmarkAccess());

  ASSERT_GT(getBenchmark_BM_time_clock_gettime_syscall(), 0);
  ASSERT_GT(getBenchmark_BM_time_clock_gettime_MONOTONIC_RAW(), 0);
  ASSERT_GT(getBenchmark_BM_time_clock_gettime_syscall(),
            getBenchmark_BM_time_clock_gettime_MONOTONIC_RAW() * 2);
}

TEST(liblog, time_clock_getres_is_vdso) {
  ASSERT_TRUE(getVdsoSymbol("clock_getres"));
  ASSERT_TRUE(benchmarkAccess());

  int64_t BM_time_clock_getres_MONOTONIC_syscall =
      getBenchmark("BM_time_clock_getres_MONOTONIC_syscall");
  ASSERT_GT(BM_time_clock_getres_MONOTONIC_syscall, 0);
  int64_t BM_time_clock_getres_MONOTONIC =
      getBenchmark("BM_time_clock_getres_MONOTONIC");
  ASSERT_GT(BM_time_clock_getres_MONOTONIC, 0);
  ASSERT_GT(BM_time_clock_getres_MONOTONIC_syscall,
            BM_time_clock_getres_MONOTONIC * 3);
}

TEST(liblog, time_time_is_vdso) {
  ASSERT_TRUE(getVdsoSymbol("time"));
  ASSERT_TRUE(benchmarkAccess());

  int64_t BM_time_clock_gettime_FASTEST =
      getBenchmark_BM_time_clock_gettime_syscall();
  int64_t BM = getBenchmark_BM_time_clock_gettime_MONOTONIC();
  if ((BM_time_clock_gettime_FASTEST < 0) ||
      (BM_time_clock_gettime_FASTEST > BM)) {
    BM_time_clock_gettime_FASTEST = BM;
  }
  BM = getBenchmark_BM_time_clock_gettime_REALTIME();
  if ((BM_time_clock_gettime_FASTEST < 0) ||
      (BM_time_clock_gettime_FASTEST > BM)) {
    BM_time_clock_gettime_FASTEST = BM;
  }
  BM = getBenchmark_BM_time_clock_gettime_BOOTTIME();
  if ((BM_time_clock_gettime_FASTEST < 0) ||
      (BM_time_clock_gettime_FASTEST > BM)) {
    BM_time_clock_gettime_FASTEST = BM;
  }
  BM = getBenchmark_BM_time_clock_gettime_MONOTONIC_RAW();
  if ((BM_time_clock_gettime_FASTEST < 0) ||
      (BM_time_clock_gettime_FASTEST > BM)) {
    BM_time_clock_gettime_FASTEST = BM;
  }
  ASSERT_GT(BM_time_clock_gettime_FASTEST, 0);
  int64_t BM_time_time = getBenchmark("BM_time_time");
  ASSERT_GT(BM_time_time, 0);
  // generally much faster, but at least 10% faster is good stuff.
  ASSERT_GT(BM_time_clock_gettime_FASTEST, BM_time_time * 11 / 10);
}

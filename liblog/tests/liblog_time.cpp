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
#include <sched.h>
#include <stdio.h>
#include <unistd.h>

#include <string>

#include <android-base/file.h>
#include <gtest/gtest.h>
#include <private/android_filesystem_config.h>

#define INCLUDED_IN_GTEST
#include "liblog_benchmark.cpp"

using namespace android::base;

// anonymous namespace houses all the local helper functions

namespace {

constexpr char warning[] = "[ WARNING  ] ";
constexpr char info[] = "[ INFO     ] ";

// More consistent measurement/benchmarking result if we
// do not hop from cpu to cpu to perform the iterations.
void setAffinityCurrent() {
#ifdef _SC_NPROCESSORS_CONF
  long numCpus = sysconf(_SC_NPROCESSORS_CONF);
#else
  int numCpus = 32;
#endif
  int cpu = sched_getcpu();
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
  long numCpus = sysconf(_SC_NPROCESSORS_CONF);
#else
  int numCpus = 32;
#endif
  int cpu = sched_getcpu();
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

long getBenchmark(const std::string& bench) {
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

  return std::stoul(benchmarks.substr(pos, end));
}

// Cache results

long getBenchmark_BM_time_clock_gettime_syscall() {
  static long gettime_period;

  if (gettime_period) return gettime_period;
  gettime_period = getBenchmark("BM_time_clock_gettime_MONOTONIC_syscall");
  return gettime_period;
}

long getBenchmark_BM_time_clock_gettime_MONOTONIC() {
  static long gettime_period;

  if (gettime_period) return gettime_period;
  gettime_period = getBenchmark("BM_time_clock_gettime_MONOTONIC");
  return gettime_period;
}

long getBenchmark_BM_time_clock_gettime_REALTIME() {
  static long gettime_period;

  if (gettime_period) return gettime_period;
  gettime_period = getBenchmark("BM_time_clock_gettime_REALTIME");
  return gettime_period;
}

long getBenchmark_BM_time_clock_gettime_BOOTTIME() {
  static long gettime_period;

  if (gettime_period) return gettime_period;
  gettime_period = getBenchmark("BM_time_clock_gettime_BOOTTIME");
  return gettime_period;
}

long getBenchmark_BM_time_clock_gettime_MONOTONIC_RAW() {
  static long gettime_period;

  if (gettime_period) return gettime_period;
  gettime_period = getBenchmark("BM_time_clock_gettime_MONOTONIC_RAW");
  return gettime_period;
}

}  // namespace

TEST(liblog, time_clock_gettime_MONOTONIC_is_vdso) {
  ASSERT_TRUE(benchmarkAccess());

  ASSERT_GT(getBenchmark_BM_time_clock_gettime_syscall(), 0);
  ASSERT_GT(getBenchmark_BM_time_clock_gettime_MONOTONIC(), 0);
  ASSERT_GT(getBenchmark_BM_time_clock_gettime_syscall(),
            getBenchmark_BM_time_clock_gettime_MONOTONIC() * 2);
}

TEST(liblog, time_clock_gettime_REALTIME_is_vdso) {
  ASSERT_TRUE(benchmarkAccess());

  ASSERT_GT(getBenchmark_BM_time_clock_gettime_syscall(), 0);
  ASSERT_GT(getBenchmark_BM_time_clock_gettime_REALTIME(), 0);
  ASSERT_GT(getBenchmark_BM_time_clock_gettime_syscall(),
            getBenchmark_BM_time_clock_gettime_REALTIME() * 2);
}

TEST(liblog, time_clock_gettime_BOOTTIME_is_vdso) {
  ASSERT_TRUE(benchmarkAccess());

  ASSERT_GT(getBenchmark_BM_time_clock_gettime_syscall(), 0);
  ASSERT_GT(getBenchmark_BM_time_clock_gettime_BOOTTIME(), 0);
  ASSERT_GT(getBenchmark_BM_time_clock_gettime_syscall(),
            getBenchmark_BM_time_clock_gettime_BOOTTIME() * 2);
}

TEST(liblog, time_clock_gettime_MONOTONIC_RAW_is_vdso) {
  ASSERT_TRUE(benchmarkAccess());

  ASSERT_GT(getBenchmark_BM_time_clock_gettime_syscall(), 0);
  ASSERT_GT(getBenchmark_BM_time_clock_gettime_MONOTONIC_RAW(), 0);
  ASSERT_GT(getBenchmark_BM_time_clock_gettime_syscall(),
            getBenchmark_BM_time_clock_gettime_MONOTONIC_RAW() * 2);
}

TEST(liblog, time_clock_getres_is_vdso) {
  ASSERT_TRUE(benchmarkAccess());

  long BM_time_clock_getres_MONOTONIC_syscall =
      getBenchmark("BM_time_clock_getres_MONOTONIC_syscall");
  ASSERT_GT(BM_time_clock_getres_MONOTONIC_syscall, 0);
  long BM_time_clock_getres_MONOTONIC =
      getBenchmark("BM_time_clock_getres_MONOTONIC");
  ASSERT_GT(BM_time_clock_getres_MONOTONIC, 0);
  ASSERT_GT(BM_time_clock_getres_MONOTONIC_syscall,
            BM_time_clock_getres_MONOTONIC * 3);
}

TEST(liblog, time_time_is_vdso) {
  ASSERT_TRUE(benchmarkAccess());

  long BM_time_clock_gettime_FASTEST =
      getBenchmark_BM_time_clock_gettime_syscall();
  long BM = getBenchmark_BM_time_clock_gettime_MONOTONIC();
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
  long BM_time_time = getBenchmark("BM_time_time");
  ASSERT_GT(BM_time_time, 0);
  // generally much faster, but at least 10% faster is good stuff.
  ASSERT_GT(BM_time_clock_gettime_FASTEST, BM_time_time * 11 / 10);
}

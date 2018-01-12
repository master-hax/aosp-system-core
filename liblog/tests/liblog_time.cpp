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
#include <stdio.h>

#include <string>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <gtest/gtest.h>
#include <log/log_time.h>
#include <private/android_filesystem_config.h>

#define INCLUDED_IN_GTEST
#include "liblog_benchmark.cpp"

using namespace android::base;

// anonymous namespace houses all the local helper functions

namespace {

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
  benchmark::RunSpecifiedBenchmarks(&output);
  std::string str = out.str();
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

unsigned long long ns(const timespec& ts) {
  return (static_cast<unsigned long long>(ts.tv_sec) * NS_PER_SEC) + ts.tv_nsec;
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
            BM_time_clock_getres_MONOTONIC * 5);
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
  ASSERT_GT(BM_time_clock_gettime_FASTEST, BM_time_time * 3);
}

TEST(liblog, time_drift) {
  // Adjust following to affect expected accuracy of the results
  static constexpr unsigned duration = 20;
  static constexpr size_t sums = 32;
  struct spec {
    clockid_t id;
    const char* name;
    unsigned long long start;
    unsigned long long end;
    unsigned long long diff;
  } spec[] = {
    // clang-format off
    { CLOCK_MONOTONIC_RAW, "MONOTONIC_RAW", 0, 0, 0 },  // first, no drift adj.
    { CLOCK_MONOTONIC,     "MONOTONIC",     0, 0, 0 },
    { CLOCK_REALTIME,      "REALTIME",      0, 0, 0 },
    { CLOCK_BOOTTIME,      "BOOTTIME",      0, 0, 0 },
    // clang-format on
  };
  timespec ts;

  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  unsigned long long start_span = ns(ts);
  for (size_t j = 0; j < sums; ++j) {
    for (size_t i = 0; i < arraysize(spec); ++i) {
      clock_gettime(spec[i].id, &ts);
      spec[i].start += ns(ts);
    }
  }
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  start_span = ns(ts) - start_span;
  sleep(duration);
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  unsigned long long end_span = ns(ts);
  for (size_t j = 0; j < sums; ++j) {
    for (size_t i = 0; i < arraysize(spec); ++i) {
      clock_gettime(spec[i].id, &ts);
      spec[i].end += ns(ts);
    }
  }
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  end_span = ns(ts) - end_span;

  // Compensate for difference in processor performance between acquisition
  // runs.  This is to allow us to run this test without cpu frequency locked.
  // Assumptions: time-to-collect is identical for all clock ids.
  for (size_t i = 0; i < arraysize(spec); ++i) {
    // major correction for established average.
    spec[i].start += start_span / 2;
    spec[i].end -= end_span / 2;
    // minor additional correction for variation in performance.
    //   2/3 of difference experimentally determined approximates the
    //   affect, feel free to explore the ratio between start_span and
    //   end_span to refine in the future.  If you _need_ an accurate
    //   result, you _must_ lock the clocks.
    long long diff = end_span - start_span;
    diff *= i * 2;
    diff /= (arraysize(spec) - 1) * 3;
    if (diff < 0) diff = -diff;
    spec[i].end -= diff;
  }

  unsigned long long max = 0, min = ULLONG_MAX;
  for (size_t i = 0; i < arraysize(spec); ++i) {
    unsigned long long diff = spec[i].end - spec[i].start;
    spec[i].diff = diff;
    if (diff > max) max = diff;
    if (diff < min) min = diff;
  }

  // If drift collected is silly, either too small (no corrections ever
  // applied) or too large (something is contributing to a large time
  // correction during the test), then do not check refined values.

  bool positive = false, negative = false;
  long long sum = 0;
  unsigned long long abs = 0;
  static constexpr char info[] = "[ INFO     ] ";
  std::cerr << info
            << "estimated kernel DRIFT settings in seconds/year (0.032ppm):\n";
  for (size_t i = 0; i < arraysize(spec); ++i) {
    long long drift = spec[i].diff - spec[0].diff;
    // Diagnostic information print is seconds per year (~0.032ppm)
    std::cerr << info << std::setw(13) << std::left << spec[i].name << ": ";
    std::streamsize prec = std::cerr.precision(3);
    std::cerr << 60.0 * 60.0 * 24.0 * 365.25 * drift / spec[0].diff << '\n';
    std::cerr.precision(prec);
    if (i > 0) {
      if (drift > 0) {
        positive = true;
        abs += drift;
      } else if (drift < 0) {
        negative = true;
        abs -= drift;
      } else {
        EXPECT_NE(drift, 0) << spec[i].name;
      }
      sum += drift;
    }
  }

  static constexpr char warning[] = "[ WARNING  ] ";
  // If drift is > 1%, our calculations are likely to be meaningless.
  if ((max - min) > (sums * duration * NS_PER_SEC / 100)) {
    std::cerr << warning << "large drift: "
              << (max - min) * 100 / sums / duration / NS_PER_SEC << "%\n";
    return;
  }

  // if values are small, our calculations are likely to be meaningless.
  if (abs < (sums * duration * (arraysize(spec) - 1))) {
    std::cerr << warning
              << "negligable drift: " << abs / (arraysize(spec) - 1) / sums
              << "ns/" << duration << "s\n";
    return;
  }

  // This is the key, they are all in the same direction
  EXPECT_NE(positive, negative);
  if (negative) sum = -sum;
  // We need a minimum threshold for sum / sums / duration. Concern
  // here is that a device may in fact have a _perfect_ clock and
  // the drift is zero, or the test is performed before any clock
  // correction software has accumulated the appropriate drift
  // corrections.
  for (size_t i = 1; i < arraysize(spec); ++i) {
    long long diff = spec[i].diff - spec[0].diff;
    if (negative) diff = -diff;
    // all within a broad (+200%/-50%) range of each other to
    // confirm expected accuracy of the above results.
    EXPECT_LE(sum, diff * 3 * 3) << "          for " << spec[i].name;
    EXPECT_GE(sum, diff * 3 / 2) << "          for " << spec[i].name;
  }
}

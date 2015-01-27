/*
 * Copyright (C) 2013-2014 The Android Open Source Project
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

#include <sys/socket.h>
#include <cutils/sockets.h>
#include <log/log.h>
#include <log/logger.h>
#include <log/log_read.h>

#include "benchmark.h"

// enhanced version of LOG_FAILURE_RETRY to add support for EAGAIN and
// non-syscall libs. Since we are benchmarking, or using this in the emergency
// signal to stuff a terminating code, we do NOT want to introduce
// a syscall or usleep on EAGAIN retry.
#define LOG_FAILURE_RETRY(exp) ({  \
    typeof (exp) _rc;              \
    do {                           \
        _rc = (exp);               \
    } while (((_rc == -1)          \
           && ((errno == EINTR)    \
            || (errno == EAGAIN))) \
          || (_rc == -EINTR)       \
          || (_rc == -EAGAIN));    \
    _rc; })

/*
 *	Measure the fastest rate we can reliabley stuff print messages into
 * the log at high pressure. Expect this to be less than double the process
 * wakeup time (2ms?)
 */
static void __BM_log_maximum_retry(int iters) {
    StartBenchmarkTiming();

    for (int i = 0; i < iters; ++i) {
        LOG_FAILURE_RETRY(
            __android_log_print(ANDROID_LOG_INFO,
                                "BM_log_maximum_retry", "%d", i));
    }

    StopBenchmarkTiming();
}

static void BM_log_maximum_retry(int iters) {
    android_set_log_frontend(LOGGER_NORMAL);
    __BM_log_maximum_retry(iters);
}
BENCHMARK(BM_log_maximum_retry);

static void BM_log_maximum_retry_fifo(int iters) {
    android_set_log_frontend(LOGGER_FIFO);
    __BM_log_maximum_retry(iters);
}
BENCHMARK(BM_log_maximum_retry_fifo);

/*
 *	Measure the fastest rate we can stuff print messages into the log
 * at high pressure. Expect this to be less than double the process wakeup
 * time (2ms?)
 */
static void __BM_log_maximum(int iters) {
    StartBenchmarkTiming();

    for (int i = 0; i < iters; ++i) {
        __android_log_print(ANDROID_LOG_INFO, "BM_log_maximum", "%d", i);
    }

    StopBenchmarkTiming();
}

static void BM_log_maximum(int iters) {
    android_set_log_frontend(LOGGER_NORMAL);
    __BM_log_maximum(iters);
}
BENCHMARK(BM_log_maximum);

static void BM_log_maximum_fifo(int iters) {
    android_set_log_frontend(LOGGER_FIFO);
    __BM_log_maximum(iters);
}
BENCHMARK(BM_log_maximum_fifo);

/*
 *	Measure the time it takes to collect the time using
 * discrete acquisition under light load. Expect this to be a
 * syscall periods (2us) or data read time if zero-syscall.
 */
static void BM_clock_overhead(int iters) {
    for (int i = 0; i < iters; ++i) {
       StartBenchmarkTiming();
       StopBenchmarkTiming();
    }
}
BENCHMARK(BM_clock_overhead);

/*
 *	Measure the time it takes to form sprintf plus time using
 * discrete acquisition under light load. Expect this to be a
 * syscall periods (2us) or sprintf time if zero-syscall time.
 */
static void test_print(const char *fmt, ...) {
    va_list ap;
    char buf[1024];

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
}

static inline void logd_yield() {
   sched_yield(); // allow logd to catch up
}

static inline void logd_sleep() {
   usleep(50); // really allow logd to catch up
}

static void BM_sprintf_overhead(int iters) {
    for (int i = 0; i < iters; ++i) {
       StartBenchmarkTiming();
       test_print("BM_sprintf_overhead:%d", i);
       StopBenchmarkTiming();
       logd_yield();
    }
}
BENCHMARK(BM_sprintf_overhead);

/*
 *	Measure the time it takes to submit the android printing logging call
 * using discrete acquisition under light load. Expect this to be a dozen or so
 * syscall periods (40us) plus time to run *printf
 */
static void __BM_log_print_overhead(int iters) {
    for (int i = 0; i < iters; ++i) {
       StartBenchmarkTiming();
       __android_log_print(ANDROID_LOG_INFO, "BM_log_overhead", "%d", i);
       StopBenchmarkTiming();
       logd_yield();
    }
}

static void BM_log_print_overhead(int iters) {
    android_set_log_frontend(LOGGER_NORMAL);
    __BM_log_print_overhead(iters);
}
BENCHMARK(BM_log_print_overhead);

static void BM_log_print_overhead_fifo(int iters) {
    android_set_log_frontend(LOGGER_FIFO);
    __BM_log_print_overhead(iters);
}
BENCHMARK(BM_log_print_overhead_fifo);

/*
 *	Measure the time it takes to submit the android event logging call
 * using discrete acquisition under light load. Expect this to be a dozen or so
 * syscall periods (40us)
 */
static void __BM_log_event_overhead(int iters) {
    for (unsigned long long i = 0; i < (unsigned)iters; ++i) {
       StartBenchmarkTiming();
       __android_log_btwrite(0, EVENT_TYPE_LONG, &i, sizeof(i));
       StopBenchmarkTiming();
       logd_yield();
    }
}

static void BM_log_event_overhead(int iters) {
    android_set_log_frontend(LOGGER_NORMAL);
    __BM_log_event_overhead(iters);
}
BENCHMARK(BM_log_event_overhead);

static void BM_log_event_overhead_fifo(int iters) {
    android_set_log_frontend(LOGGER_FIFO);
    __BM_log_event_overhead(iters);
}
BENCHMARK(BM_log_event_overhead_fifo);

static void caught_latency(int /*signum*/)
{
    unsigned long long v = 0xDEADBEEFA55A5AA5ULL;

    LOG_FAILURE_RETRY(__android_log_btwrite(0, EVENT_TYPE_LONG, &v, sizeof(v)));
}

static unsigned long long caught_convert(char *cp)
{
    unsigned long long l = cp[0] & 0xFF;
    l |= (unsigned long long) (cp[1] & 0xFF) << 8;
    l |= (unsigned long long) (cp[2] & 0xFF) << 16;
    l |= (unsigned long long) (cp[3] & 0xFF) << 24;
    l |= (unsigned long long) (cp[4] & 0xFF) << 32;
    l |= (unsigned long long) (cp[5] & 0xFF) << 40;
    l |= (unsigned long long) (cp[6] & 0xFF) << 48;
    l |= (unsigned long long) (cp[7] & 0xFF) << 56;
    return l;
}

static const int alarm_time = 3;

/*
 *	Measure the time it takes for the logd posting call to acquire the
 * timestamp to place into the internal record. Expect this to be less than
 * 4 syscalls (3us).
 */
static void __BM_log_latency(int iters) {
    pid_t pid = getpid();

    struct logger_list * logger_list = android_logger_list_open(LOG_ID_EVENTS,
        O_RDONLY, 0, pid);

    if (!logger_list) {
        fprintf(stderr, "Unable to open events log: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    signal(SIGALRM, caught_latency);
    alarm(alarm_time);

    for (int j = 0, i = 0; i < iters && j < 10*iters; ++i, ++j) {
        log_time ts;
        LOG_FAILURE_RETRY((
            ts = log_time(CLOCK_REALTIME),
            android_btWriteLog(0, EVENT_TYPE_LONG, &ts, sizeof(ts))));

        for (;;) {
            log_msg log_msg;
            int ret = android_logger_list_read(logger_list, &log_msg);
            alarm(alarm_time);

            if (ret <= 0) {
                iters = i;
                break;
            }
            if ((log_msg.entry.len != (4 + 1 + 8))
             || (log_msg.id() != LOG_ID_EVENTS)) {
                continue;
            }

            char* eventData = log_msg.msg();

            if (eventData[4] != EVENT_TYPE_LONG) {
                continue;
            }
            log_time tx(eventData + 4 + 1);
            if (ts != tx) {
                if (0xDEADBEEFA55A5AA5ULL == caught_convert(eventData + 4 + 1)) {
                    iters = i;
                    break;
                }
                continue;
            }

            uint64_t start = ts.nsec();
            uint64_t end = log_msg.nsec();
            if (end >= start) {
                StartBenchmarkTiming(start);
                StopBenchmarkTiming(end);
            } else {
                --i;
            }
            break;
        }
    }

    signal(SIGALRM, SIG_DFL);
    alarm(0);

    android_logger_list_free(logger_list);
}

static void BM_log_latency(int iters) {
    android_set_log_frontend(LOGGER_NORMAL);
    __BM_log_latency(iters);
}
BENCHMARK(BM_log_latency);

static void BM_log_latency_fifo(int iters) {
    android_set_log_frontend(LOGGER_FIFO);
    __BM_log_latency(iters);
}
BENCHMARK(BM_log_latency_fifo);

static void caught_delay(int /*signum*/)
{
    unsigned long long v = 0xDEADBEEFA55A5AA6ULL;

    LOG_FAILURE_RETRY(__android_log_btwrite(0, EVENT_TYPE_LONG, &v, sizeof(v)));
}

/*
 *	Measure the time it takes for the logd posting call to make it into
 * the logs. Expect this to be less than double the process wakeup time (2ms).
 */
static void __BM_log_delay(int iters) {
    pid_t pid = getpid();

    struct logger_list * logger_list = android_logger_list_open(LOG_ID_EVENTS,
        O_RDONLY, 0, pid);

    if (!logger_list) {
        fprintf(stderr, "Unable to open events log: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    signal(SIGALRM, caught_delay);
    alarm(alarm_time);

    StartBenchmarkTiming();

    for (int i = 0; i < iters; ++i) {
        log_time ts(CLOCK_REALTIME);

        LOG_FAILURE_RETRY(
            android_btWriteLog(0, EVENT_TYPE_LONG, &ts, sizeof(ts)));

        for (;;) {
            log_msg log_msg;
            int ret = android_logger_list_read(logger_list, &log_msg);
            alarm(alarm_time);

            if (ret <= 0) {
                iters = i;
                break;
            }
            if ((log_msg.entry.len != (4 + 1 + 8))
             || (log_msg.id() != LOG_ID_EVENTS)) {
                continue;
            }

            char* eventData = log_msg.msg();

            if (eventData[4] != EVENT_TYPE_LONG) {
                continue;
            }
            log_time tx(eventData + 4 + 1);
            if (ts != tx) {
                if (0xDEADBEEFA55A5AA6ULL == caught_convert(eventData + 4 + 1)) {
                    iters = i;
                    break;
                }
                continue;
            }

            break;
        }
    }

    signal(SIGALRM, SIG_DFL);
    alarm(0);

    StopBenchmarkTiming();

    android_logger_list_free(logger_list);
}

static void BM_log_delay(int iters) {
    android_set_log_frontend(LOGGER_NORMAL);
    __BM_log_delay(iters);
}
BENCHMARK(BM_log_delay);

static void BM_log_delay_fifo(int iters) {
    android_set_log_frontend(LOGGER_FIFO);
    __BM_log_delay(iters);
}
BENCHMARK(BM_log_delay_fifo);

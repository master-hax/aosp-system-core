/*
 *  Copyright 2018 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <log/log_id.h>
#include <stats_event_list.h>
#include <statslog.h>
#include <string.h>
#include <time.h>

#define LINE_MAX 128
#define STRINGIFY(x) STRINGIFY_INTERNAL(x)
#define STRINGIFY_INTERNAL(x) #x

static bool enable_stats_log;
static android_log_context log_ctx;

static int64_t getElapsedRealTimeNs() {
    struct timespec t;
    t.tv_sec = t.tv_nsec = 0;
    clock_gettime(CLOCK_BOOTTIME, &t);
    return (int64_t)t.tv_sec * 1000000000LL + t.tv_nsec;
}

void statslog_init() {
    enable_stats_log = property_get_bool("ro.lmk.log_stats", false);

    if (enable_stats_log) {
        log_ctx = create_android_logger(kStatsEventTag);
    }
}

void statslog_destroy() {
    if (log_ctx) {
        android_log_destroy(&log_ctx);
    }
}

bool statslog_enabled() {
    return enable_stats_log;
}

/**
 * Logs the change in LMKD state which is used as start/stop boundaries for logging
 * LMK_KILL_OCCURRED event.
 * Code: LMK_STATE_CHANGED = 54
 */
int
stats_write_lmk_state_changed(int32_t code, int32_t state) {
    int ret = -EINVAL;

    if (!enable_stats_log) {
        return ret;
    }

    assert(log_ctx != NULL);
    if (!log_ctx) {
        return ret;
    }

    reset_log_context(log_ctx);

    if ((ret = android_log_write_int64(log_ctx, getElapsedRealTimeNs())) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int32(log_ctx, code)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int32(log_ctx, state)) < 0) {
        return ret;
    }

    return write_to_logger(log_ctx, LOG_ID_STATS);
}

/**
 * Logs the event when LMKD kills a process to reduce memory pressure.
 * Code: LMK_KILL_OCCURRED = 51
 */
int
stats_write_lmk_kill_occurred(int32_t code,
                              int32_t uid, char const* process_name, int32_t oom_score,
                              int32_t min_oom_score, int tasksize, struct memory_stat *mem_st) {
    int ret = -EINVAL;

    if (!enable_stats_log) {
        return ret;
    }

    assert(log_ctx != NULL);
    if (!log_ctx) {
        return ret;
    }
    reset_log_context(log_ctx);

    if ((ret = android_log_write_int64(log_ctx, getElapsedRealTimeNs())) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int32(log_ctx, code)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int32(log_ctx, uid)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_string8(log_ctx, (process_name == NULL) ? "" : process_name)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int32(log_ctx, oom_score)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int64(log_ctx, mem_st ? mem_st->pgfault : -1)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int64(log_ctx, mem_st ? mem_st->pgmajfault : -1)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int64(log_ctx, mem_st ? mem_st->rss_in_bytes
                                                          : tasksize * BYTES_IN_KILOBYTE)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int64(log_ctx, mem_st ? mem_st->cache_in_bytes : -1)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int64(log_ctx, mem_st ? mem_st->swap_in_bytes : -1)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int64(log_ctx, mem_st ? mem_st->process_start_time_ns
                                                          : -1)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int32(log_ctx, min_oom_score)) < 0) {
        return ret;
    }

    return write_to_logger(log_ctx, LOG_ID_STATS);
}

static void memory_stat_parse_line(char* line, struct memory_stat* mem_st) {
    char key[LINE_MAX + 1];
    int64_t value;

    sscanf(line, "%" STRINGIFY(LINE_MAX) "s  %" SCNd64 "", key, &value);

    if (strcmp(key, "total_") < 0) {
        return;
    }

    if (!strcmp(key, "total_pgfault"))
        mem_st->pgfault = value;
    else if (!strcmp(key, "total_pgmajfault"))
        mem_st->pgmajfault = value;
    else if (!strcmp(key, "total_rss"))
        mem_st->rss_in_bytes = value;
    else if (!strcmp(key, "total_cache"))
        mem_st->cache_in_bytes = value;
    else if (!strcmp(key, "total_swap"))
        mem_st->swap_in_bytes = value;
}

static int memory_stat_from_cgroup(struct memory_stat* mem_st, int pid, uid_t uid) {
    FILE *fp;
    char buf[PATH_MAX];

    snprintf(buf, sizeof(buf), MEMCG_PROCESS_MEMORY_STAT_PATH, uid, pid);

    fp = fopen(buf, "r");

    if (fp == NULL) {
        return -1;
    }

    while (fgets(buf, PAGE_SIZE, fp) != NULL) {
        memory_stat_parse_line(buf, mem_st);
    }
    fclose(fp);

    return 0;
}

static int memory_stat_from_procfs(struct memory_stat* mem_st, int pid) {
    char path[PATH_MAX];
    char buffer[PROC_STAT_BUFFER_SIZE];
    int fd, ret;

    snprintf(path, sizeof(path), PROC_STAT_FILE_PATH, pid);
    if ((fd = open(path, O_RDONLY | O_CLOEXEC)) < 0) {
        return -1;
    }

    ret = read(fd, buffer, sizeof(buffer));
    if (ret < 0) {
        close(fd);
        return -1;
    }
    close(fd);

    // field 10 is pgfault
    // field 12 is pgmajfault
    // field 22 is starttime
    // field 24 is rss_in_pages
    int64_t pgfault = 0, pgmajfault = 0, starttime = 0, rss_in_pages = 0;
    if (sscanf(buffer,
               "%*u %*s %*s %*d %*d %*d %*d %*d %*d %" SCNd64 " %*d "
               "%" SCNd64 " %*d %*u %*u %*d %*d %*d %*d %*d %*d "
               "%" SCNd64 " %*d %" SCNd64 "",
               &pgfault, &pgmajfault, &starttime, &rss_in_pages) != 4) {
        return -1;
    }
    mem_st->pgfault = pgfault;
    mem_st->pgmajfault = pgmajfault;
    mem_st->rss_in_bytes = (rss_in_pages * PAGE_SIZE);
    mem_st->process_start_time_ns = starttime * (NS_PER_SEC / sysconf(_SC_CLK_TCK));

    return 0;
}

struct memory_stat *stats_read_memory_stat(bool per_app_memcg, int pid, uid_t uid) {
    static struct memory_stat mem_st = {};

    if (!enable_stats_log) {
        return NULL;
    }

    if (per_app_memcg) {
        if (memory_stat_from_cgroup(&mem_st, pid, uid) == 0) {
            return &mem_st;
        }
    } else {
        if (memory_stat_from_procfs(&mem_st, pid) == 0) {
            return &mem_st;
        }
    }

    return NULL;
}

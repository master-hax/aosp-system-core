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

/*
 * In order to mutually influence the behavior of each other,
 * Linux and Trusty use a shared-memory based data-structure
 * that contains information such as per-CPU 'shadow-priority'.
 * A test is required to verify that, as trusty thread priorities
 * change on a particular CPU, it is correspondingly reflected
 * through 'shadow-priority' in the shared-memory. As such, the
 * test must have 2 components implemented as client-server pair.
 * A linux client test app can request the trusty-side test-server,
 * to set priority of the test thread to a specific value while
 * executing on a particular CPU. When the server thread responds
 * to this request, the linux client can verify the reflected
 * 'shadow-priority' by reading the value from the shared-memory.
 * This module implements the Linux-side client test app.
 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define __USE_GNU

#include "shadoprio_test.h"

static char* shprio_bufs[TRUSTY_MAX_CPUS];
static uint cpu_count;

static int fetch_debugfs_data(uint* buf_count_p) {
    FILE* dbgfs_fp;
    ssize_t read_len;
    size_t read_max;

    *buf_count_p = 0;

    dbgfs_fp = fopen(SHPRIO_DEBUGFS_PATH, "r");
    if (!dbgfs_fp) {
        fprintf(stderr, "%s: Failed to open '%s' for read!\n", __func__, SHPRIO_DEBUGFS_PATH);
        return ERROR;
    }

    while (*buf_count_p < TRUSTY_MAX_CPUS) {
        if (shprio_bufs[*buf_count_p] == NULL) {
            continue;
        }
        read_max = SHPRIO_DEBUGFS_MAX_LINE_SIZE;
        memset(shprio_bufs[*buf_count_p], 0, read_max);

        read_len = getline(&shprio_bufs[*buf_count_p], &read_max, dbgfs_fp);
        if (read_len < 0) {
            DBGTRC(5, "%s: getline() error or EOF read_len=%d\n", __func__, (int)read_len);
            break;
        } else if (read_len == 0) {
            continue;
        }
        DBGTRC(75, "%s: buf[%d]: %s", __func__, *buf_count_p, shprio_bufs[*buf_count_p]);
        *buf_count_p += 1;
    }

    fclose(dbgfs_fp);
    return NO_ERROR;
}

static int parse_cpu_id(char* linebuf) {
    char* toks; /* start of token */
    char* toke; /* end of token */
    int cpu_id;
    char save;

    cpu_id = -1;
    toks = strchr(linebuf, '[');
    if (!toks) {
        return cpu_id;
    }
    toks++;

    toke = strchr(toks, ']');
    if (!toke) {
        return cpu_id;
    }
    save = *toke;
    *toke = '\0';

    cpu_id = atoi(toks);
    *toke = save;

    DBGTRC(75, "%s: cpu_id=%d\n", __func__, cpu_id);
    return cpu_id;
}

static void get_debugfs_cpu_count(uint buf_count) {
    uint buf_id;
    int rv;

    DBGTRC(15, "%s: buf_count=%d\n", __func__, buf_count);

    cpu_count = 0;

    for (buf_id = 0; buf_id < buf_count; buf_id++) {
        char* linebuf = shprio_bufs[buf_id];
        DBGTRC(75, "%s: shprio_buf[%d]=%p\n", __func__, buf_id, linebuf);
        assert(NULL != linebuf);

        rv = parse_cpu_id(linebuf);
        if (rv >= 0) {
            if (++rv > cpu_count) {
                cpu_count = rv;
            }
        }
    }
    if (cpu_count > TRUSTY_MAX_CPUS) {
        cpu_count = TRUSTY_MAX_CPUS;
    }
    DBGTRC(15, "%s: cpu_count=%d\n", __func__, cpu_count);
}

static char* find_token(char* buf, const char* token) {
    uint i;
    size_t tok_len;
    char* tok_pos;
    if ((!buf) || (!token)) {
        return NULL;
    }

    DBGTRC(65, "%s: token:'%s' buf:'%s'", __func__, token, buf);

    tok_len = strlen(token);
    if (tok_len < 1) {
        return NULL;
    }

    for (i = 0;; i++) {
        tok_pos = &buf[i];
        DBGTRC(95, "%s: tok_pos:'%s'\n", __func__, tok_pos);

        if (strncmp(tok_pos, token, tok_len) == 0) {
            DBGTRC(75, "%s: got a MATCH!!\n", __func__);
            return tok_pos;
        }
        if (strlen(tok_pos) <= tok_len) {
            break;
        }
    }
    return NULL;
}

static uint parse_shadow_priority(char* linebuf) {
    uint shprio;
    char* toks; /* start of token */

    DBGTRC(65, "%s: linebuf=%s", __func__, linebuf);

    shprio = 4;
    toks = find_token(linebuf, "ask_priority=");
    if (!toks) {
        return shprio;
    }
    DBGTRC(65, "%s: tokpos='%s'\n", __func__, toks);

    toks += strlen("ask_priority=");
    shprio = atoi(toks);
    return shprio;
}

int shprio_debugfs_get_shadow_priority(uint cpu_id, uint* shprio_p) {
    uint buf_count;
    uint buf_id;
    int rv;

    DBGTRC(55, "%s: cpu_id=%d\n", __func__, cpu_id);

    /* init the output with a marker invalid value */
    *shprio_p = TRUSTY_SHADOW_PRIORITY_HIGH + 1;

    if (ERROR == fetch_debugfs_data(&buf_count)) return ERROR;

    for (buf_id = 0; buf_id < buf_count; buf_id++) {
        char* linebuf = shprio_bufs[buf_id];
        assert(NULL != linebuf);

        rv = parse_cpu_id(linebuf);
        if (rv != cpu_id) {
            DBGTRC(65, "%s: no match rv=%d cpu_id=%d\n", __func__, rv, cpu_id);
            continue;
        }

        DBGTRC(55, "%s: match rv=%d cpu_id=%d\n", __func__, rv, cpu_id);

        *shprio_p = parse_shadow_priority(linebuf);
        break;
    }
    return NO_ERROR;
}

uint shprio_debugfs_map_shadow_priority(uint priority) {
    uint shadow_priority;

    if (priority <= TRUSTY_LOW_PRIORITY) {
        shadow_priority = TRUSTY_SHADOW_PRIORITY_LOW;
    } else if (priority >= TRUSTY_HIGH_PRIORITY) {
        shadow_priority = TRUSTY_SHADOW_PRIORITY_HIGH;
    } else {
        shadow_priority = TRUSTY_SHADOW_PRIORITY_NORMAL;
    }
    return shadow_priority;
}

uint shprio_debugfs_get_cpu_count(void) {
    return cpu_count;
}

void shprio_debugfs_fini(void) {
    uint cpu_id;

    for (cpu_id = 0; cpu_id < TRUSTY_MAX_CPUS; cpu_id++) {
        assert(NULL != shprio_bufs[cpu_id]);
        free(shprio_bufs[cpu_id]);
    }
}

void shprio_debugfs_init(void) {
    uint buf_id;
    uint buf_count;

    cpu_count = 0;

    for (buf_id = 0; buf_id < TRUSTY_MAX_CPUS; buf_id++) {
        shprio_bufs[buf_id] = malloc(SHPRIO_DEBUGFS_MAX_LINE_SIZE);
    }
    if (ERROR == fetch_debugfs_data(&buf_count)) {
        DBGTRC(5, "%s: failed to fetch debugfs data\n", __func__);
        exit(1);
    }

    get_debugfs_cpu_count(buf_count);
}

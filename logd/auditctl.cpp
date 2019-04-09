/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "libaudit.h"

static void usage(const char* cmdline) {
    fprintf(stderr, "Usage: %s [-r rate]\n", cmdline);
}

static void do_update_rate(int rate) {
    if (rate < 0 || rate > UINT32_MAX) {
        fprintf(stderr, "invalid rate: %d\n", rate);
        exit(EXIT_FAILURE);
    }
    uint32_t urate = static_cast<uint32_t>(rate);
    int fd = audit_open();
    if (fd == -1) {
        perror("Unable to open audit socket");
        exit(EXIT_FAILURE);
    }
    int result = audit_rate_limit(fd, urate);
    close(fd);
    if (result < 0) {
        fprintf(stderr, "Can't update audit rate limit: %d\n", result);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char* argv[]) {
    int rate = 0;
    bool update_rate = false;
    int opt;

    while ((opt = getopt(argc, argv, "r:")) != -1) {
        switch (opt) {
            case 'r':
                rate = atoi(optarg);
                update_rate = true;
                break;
            default: /* '?' */
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (update_rate) {
        do_update_rate(rate);
    }

    exit(EXIT_SUCCESS);
}

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

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <trusty/lib/loader.h>
#include <trusty/tipc.h>

#define TIPC_DEFAULT_DEVNAME "/dev/trusty-ipc-dev0"

static const char* dev_name = NULL;
static const char* app = NULL;
static int op;

enum ops {
    OP_LOAD,
    OP_UNLOAD,
};

static const char* _sopts = "hD:l:u:";
static const struct option _lopts[] = {
        {"help", no_argument, 0, 'h'},
        {"load", required_argument, 0, 'l'},
        {"unload", required_argument, 0, 'u'},
        {"dev", required_argument, 0, 'D'},
        {0, 0, 0, 0},
};

static const char* usage =
        "Usage: %s -l|-u [-D devname] arg\n"
        "\n"
        "options:\n"
        "  -l, --load package    Package to load\n"
        "  -u, --unload uuid     UUID of the package to unload\n"
        "  -D, --dev name        Trusty device name\n"
        "  -h, --help            prints this message and exit\n"
        "\n";

static void print_usage_and_exit(const char* prog, int code) {
    fprintf(stderr, usage, prog);
    exit(code);
}

static void parse_options(int argc, char** argv) {
    int c;
    int oidx = 0;

    while (1) {
        c = getopt_long(argc, argv, _sopts, _lopts, &oidx);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'l':
                if (app) {
                    print_usage_and_exit(argv[0], EXIT_FAILURE);
                }
                app = strdup(optarg);
                op = OP_LOAD;
                break;
            case 'u':
                if (app) {
                    print_usage_and_exit(argv[0], EXIT_FAILURE);
                }
                app = strdup(optarg);
                op = OP_UNLOAD;
                break;
            case 'D':
                dev_name = strdup(optarg);
                break;
            case 'h':
                print_usage_and_exit(argv[0], EXIT_SUCCESS);
                break;
            default:
                print_usage_and_exit(argv[0], EXIT_FAILURE);
        }
    }
}

static int process_load() {
    int rc;
    rc = loader_load(dev_name, app);
    if (rc) {
        fprintf(stderr, "Load failed: %s\n", loader_error_to_str(rc));
    }

    return rc;
}

static int process_unload() {
    int rc;
    rc = loader_unload(dev_name, app);
    if (rc) {
        fprintf(stderr, "Unload failed: %s\n", loader_error_to_str(rc));
    }

    return rc;
}

static int process_op() {
    int ret;

    switch (op) {
        case OP_LOAD:
            ret = process_load();
            break;
        case OP_UNLOAD:
            ret = process_unload();
            break;
        default:
            fprintf(stderr, "Invalid operation %d\n", op);
            ret = -1;
    }

    return ret;
}

int main(int argc, char** argv) {
    int rc = 0;

    if (argc <= 1) {
        print_usage_and_exit(argv[0], EXIT_FAILURE);
    }

    parse_options(argc, argv);

    if (!app) {
        print_usage_and_exit(argv[0], EXIT_FAILURE);
    }

    if (!dev_name) {
        dev_name = TIPC_DEFAULT_DEVNAME;
    }

    rc = process_op();

    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

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

#include <errno.h>
#include <getopt.h>
#include <json/json.h>
#include <log/log.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <trusty/busy_test/busy_test_client.h>
#include <trusty/tipc.h>
#include <unistd.h>

#define TIPC_DEFAULT_DEVNAME "/dev/trusty-ipc-dev0"

static const char* dev_name = NULL;
static const char* json_cfg = NULL;

static const char* _sopts = "hD:C:";
static const struct option _lopts[] = {
        {"help", no_argument, 0, 'h'},
        {"dev", required_argument, 0, 'D'},
        {"cfg", required_argument, 0, 'C'},
        {0, 0, 0, 0},
};

static const char* usage =
        "Usage: %s [options] unittest-app\n"
        "\n"
        "options:\n"
        "  -h, --help            prints this message and exit\n"
        "  -D, --dev name        Trusty device name\n"
        "  -C, --cfg json blob   busy-test config in json\n"
        "                        dictionary of {cpu:priority}\n"
        "\n";

static const char* usage_long = "\n";

static void print_usage_and_exit(const char* prog, int code, bool verbose) {
    fprintf(stderr, usage, prog);
    if (verbose) {
        fprintf(stderr, "%s", usage_long);
    }
    exit(code);
}

static void parse_options(int argc, char** argv) {
    int c;
    int oidx = 0;

    while (1) {
        c = getopt_long(argc, argv, _sopts, _lopts, &oidx);
        if (c == -1) {
            break; /* done */
        }

        switch (c) {
            case 'D':
                dev_name = strdup(optarg);
                break;

            case 'C':
                json_cfg = strdup(optarg);
                ALOGD("%s", json_cfg);
                break;

            case 'h':
                print_usage_and_exit(argv[0], EXIT_SUCCESS, true);
                break;

            default:
                print_usage_and_exit(argv[0], EXIT_FAILURE, false);
        }
    }
}

inline bool CStringToUInt32(const char* s, uint32_t* value, int base = 10) {
    char* endptr = nullptr;
    auto value_maybe = static_cast<uint32_t>(strtoul(s, &endptr, base));
    if (*s && !*endptr) {
        *value = value_maybe;
        return true;
    }
    return false;
}

static bool parse_json_object(Json::Value& root, Json::String& strCpu, uint32_t* cpu,
                              uint32_t* priority) {
    assert(cpu);
    assert(priority);
    if (!CStringToUInt32(strCpu.c_str(), cpu)) {
        fprintf(stderr, "Invalid cpu key %s\n", strCpu.c_str());
        return false;
    }
    auto vPriorityDefault = Json::Value(Json::UInt(0));
    Json::StreamWriterBuilder builder;
    auto vPriority = root.get(strCpu, vPriorityDefault);
    if (!vPriority.isUInt()) {
        fprintf(stderr, "Invalid Unsigned Integer value \"%s\" for key \"%s\"\n",
                Json::writeString(builder, vPriority).c_str(), strCpu.c_str());
        return false;
    }
    *priority = vPriority.asUInt();
    return true;
}

static int parse_json_config(int fd, const char* cfg) {
    Json::Value root;
    Json::Reader reader;
    assert(cfg);
    ALOGD("%s", cfg);
    if (!reader.parse(cfg, root)) {
        fprintf(stderr, "Failed to parse: %s\n", cfg);
        return -1;
    }

    if (!root.isObject()) {
        fprintf(stderr, "Non-object JSON received: %s\n", cfg);
        return -1;
    }
    auto members = root.getMemberNames();
    auto rc = std::all_of(members.begin(), members.end(), [&fd, &root](Json::String& member) {
        uint32_t cpu, priority;
        if (!parse_json_object(root, member, &cpu, &priority)) {
            return false;
        }
        auto rc = busy_test_set_priority(fd, cpu, priority);
        if (rc != BUSY_TEST_NO_ERROR) {
            fprintf(stderr, "busy_test_set_priority failed (%d)\n", rc);
        }
        return rc == BUSY_TEST_NO_ERROR ? true : false;
    });

    return rc ? 0 : -1;
}

static int run_trusty_busy_test(const char* json_cfg_at_start) {
    int fd;
    int rc = 0;
    char input[128];
    const char* json_cfg = json_cfg_at_start;
    /* connect to unitest app */
    fd = tipc_connect(dev_name, BUSY_TEST_PORT);
    if (fd < 0) {
        fprintf(stderr, "failed to connect to '%s' app: %s\n", BUSY_TEST_PORT, strerror(-fd));
        return fd;
    }
    while (true) {
        if (json_cfg) {
            rc = parse_json_config(fd, json_cfg);
            if (rc != 0) {
                break;
            }
        }
        if (!fgets(input, sizeof(input) - 1, stdin)) {
            break;
        }
        if (input[0] == 'q') {
            break;
        }
        json_cfg = input;
    }

    /* close connection to unitest app */
    tipc_close(fd);
    return rc;
}

int main(int argc, char** argv) {
    int rc = 0;

    if (argc <= 1) {
        print_usage_and_exit(argv[0], EXIT_FAILURE, false);
    }

    parse_options(argc, argv);

    if (!dev_name) {
        dev_name = TIPC_DEFAULT_DEVNAME;
    }

    rc = run_trusty_busy_test(json_cfg);
    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

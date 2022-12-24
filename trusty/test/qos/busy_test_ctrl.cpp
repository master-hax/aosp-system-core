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
        "  -C, --cfg json blob   busy-test config as:\n"
        "                        - a json dictionary of\n"
        "                           - {cpu:priority}\n"
        "                           - or {\"sleep\":duration_sec}\n"
        "                        - or a json array with a sequence\n"
        "                          of above commands\n"
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

static bool parse_json_object_member(int fd, Json::Value& value, Json::String& member) {
    /* parse string command (sleep) */
    Json::StreamWriterBuilder builder;
    auto vDefaultZero = Json::Value(Json::UInt(0));
    if (member.compare("sleep") == 0) {
        auto vDuration = value.get(member, vDefaultZero);
        if (!vDuration.isUInt()) {
            fprintf(stderr, "Invalid Unsigned Integer value \"%s\" for key \"%s\"\n",
                    Json::writeString(builder, vDuration).c_str(), member.c_str());
            return false;
        }
        uint32_t duration = vDuration.asUInt();
        sleep(duration);
        return true;
    }
    /* parse cpu:priority object */
    uint32_t cpu, priority;
    if (!CStringToUInt32(member.c_str(), &cpu)) {
        fprintf(stderr, "Invalid cpu key %s\n", member.c_str());
        return false;
    }
    auto vPriority = value.get(member, vDefaultZero);
    if (!vPriority.isUInt()) {
        fprintf(stderr, "Invalid Unsigned Integer value \"%s\" for key \"%s\"\n",
                Json::writeString(builder, vPriority).c_str(), member.c_str());
        return false;
    }
    priority = vPriority.asUInt();
    auto rc = busy_test_set_priority(fd, cpu, priority);
    if (rc != BUSY_TEST_NO_ERROR) {
        fprintf(stderr, "busy_test_set_priority failed (%d)\n", rc);
    }
    return rc == BUSY_TEST_NO_ERROR ? true : false;
}

static bool parse_json_object(int fd, const char* cfg, Json::Value& value) {
    if (!value.isObject()) {
        fprintf(stderr, "Non-object JSON received: %s\n", cfg);
        return false;
    }
    auto members = value.getMemberNames();
    auto rc = std::all_of(members.begin(), members.end(), [&fd, &value](Json::String& member) {
        if (!parse_json_object_member(fd, value, member)) {
            return false;
        }
        return true;
    });
    return rc;
}

static int parse_json_config(int fd, const char* cfg) {
    Json::Value root;
    Json::Reader reader;
    bool rc = true;
    assert(cfg);
    ALOGD("%s", cfg);
    if (!reader.parse(cfg, root)) {
        fprintf(stderr, "Failed to parse: %s\n", cfg);
        return -1;
    }
    if (root.isArray()) {
        auto it = root.begin();
        while (it != root.end()) {
            rc = parse_json_object(fd, cfg, *it++);
            if (!rc) {
                break;
            }
        }
    } else {
        rc = parse_json_object(fd, cfg, root);
    }

    return rc ? 0 : -1;
}

static int run_trusty_busy_test(const char* json_cfg_at_start) {
    int fd;
    int rc;
    char input[128];
    const char* json_cfg = json_cfg_at_start;

    /* connect to busy-test app */
    rc = busy_test_connect(dev_name, &fd);
    if (rc != 0) {
        return rc;
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

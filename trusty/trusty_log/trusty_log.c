/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define LOG_TAG "TrustyLog"

#include <errno.h>
#include <getopt.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trusty_log.h"

/* trusty log debugfs file */
static const char TRUSTY_LOG_FILE[] = "/trusty_logs/trusty_debug.log";

/* trusty logs output file, default stdout is used for printing logs */
FILE* tlog_out_file = NULL;

/* log filter attributes */
struct trusty_log_filter {
    uint32_t log_level;
    uint32_t app_id;
    char* app_name;
};

static struct trusty_log_filter tlog_filter = {.log_level = 0, .app_id = -1, .app_name = NULL};

static const char* _sopts = "hailo:";
static const struct option _lopts[] = {
        {"help", no_argument, 0, 'h'},         {"app", required_argument, 0, 'a'},
        {"app_id", required_argument, 0, 'i'}, {"log_level", required_argument, 0, 'l'},
        {"out", required_argument, 0, 'o'},    {0, 0, 0, 0},
};

static const char* usage =
        "Usage: %s [options]\n"
        "\n"
        "options:\n"
        "  -h, --help            prints this message and exit\n"
        "  -a, --app             Trusty app name\n"
        "  -i, --app_id          Trusty app id\n"
        "  -l, --log_level       Trusty log level\n"
        "  -o, --out             Trusty log output file\n"
        "\n";

static void print_usage_and_exit(const char* prog, int code) {
    fprintf(stderr, usage, prog);
    exit(code);
}

static void create_trusty_log_out_file(char* filename) {
    tlog_out_file = fopen(filename, "w");
    if (tlog_out_file == NULL) {
        fprintf(stderr, "Failed to create output file: %s\n", filename);
        fprintf(stderr, "Error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static void parse_options(int argc, char** argv) {
    int c;
    int oidx = 0;
    char* out_file = NULL;

    while (1) {
        c = getopt_long(argc, argv, _sopts, _lopts, &oidx);
        if (c == -1) {
            break; /* done */
        }

        switch (c) {
            case 'h':
                print_usage_and_exit(argv[0], EXIT_SUCCESS);
                break;

            case 'a':
                tlog_filter.app_name = strdup(optarg);
                break;

            case 'i':
                tlog_filter.app_id = atoi(optarg);
                break;

            case 'l':
                tlog_filter.log_level = atoi(optarg);
                break;

            case 'o':
                out_file = strdup(optarg);
                create_trusty_log_out_file(out_file);
                free(out_file);
                break;

            default:
                print_usage_and_exit(argv[0], EXIT_FAILURE);
        }
    }
}

static void trusty_filter_print_log(struct log_data_footer footer, char* app_name, char* log_text) {
    if (tlog_filter.app_name) {
        if (app_name == NULL || strcmp(tlog_filter.app_name, app_name) != 0) {
            return;
        }
    }

    if (tlog_filter.app_id != -1) {
        if (tlog_filter.app_id != footer.app_id) return;
    }

    if (tlog_filter.log_level > 0) {
        if (tlog_filter.log_level != footer.log_level) return;
    }

    if (app_name) {
        fprintf(tlog_out_file, "%lu: %s: %s", footer.timestamp, app_name, log_text);
    } else {
        fprintf(tlog_out_file, "%lu: %s", footer.timestamp, log_text);
    }
}

static int trusty_debugfs_read_logs(char* trusty_debugfs_log_file) {
    FILE* f;
    char* app_name = NULL;
    char buff[256] = {};
    char log_text[256] = {};
    struct log_data_footer footer;
    int i = 0;

    f = fopen(trusty_debugfs_log_file, "r");
    if (!f) {
        fprintf(stderr, "read from gpio debugfs failed");
        return EXIT_FAILURE;
    }

    while (fread(&footer, sizeof(struct log_data_footer), 1, f)) {
        if (fread(buff, (footer.log_len + footer.app_name_len), 1, f)) {
            if (footer.app_name_len > 0) {
                app_name = &buff[footer.log_len];
            }
            for (i = 0; i < footer.log_len; i++) {
                log_text[i] = buff[i];
            }
            log_text[++i] = '\0';

            trusty_filter_print_log(footer, app_name, log_text);

            app_name = NULL;
            memset(buff, 0, sizeof(buff));
            memset(log_text, 0, sizeof(log_text));
        }
    }
    fclose(f);

    return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
    int ret = EXIT_SUCCESS;
    struct mntent* m;
    FILE* f;
    char* trusty_debugfs_log_file = NULL;

    parse_options(argc, argv);

    /* get trusty logs debugfs path */
    f = setmntent(_PATH_MOUNTED, "r");
    while ((m = getmntent(f))) {
        if (strcmp(m->mnt_fsname, "debugfs") == 0) {
            trusty_debugfs_log_file =
                    (char*)malloc((strlen(m->mnt_dir) + strlen(TRUSTY_LOG_FILE) + 1));
            strcpy(trusty_debugfs_log_file, m->mnt_dir);
            strcat(trusty_debugfs_log_file, TRUSTY_LOG_FILE);
            break;
        }
    }
    endmntent(f);

    if (trusty_debugfs_log_file == NULL) {
        fprintf(stderr, "failed to get debugfs mount path");
        return EXIT_FAILURE;
    }

    if (tlog_out_file == NULL) {
        tlog_out_file = stdout;
    }
    ret = trusty_debugfs_read_logs(trusty_debugfs_log_file);

    if (trusty_debugfs_log_file) {
        free(trusty_debugfs_log_file);
        trusty_debugfs_log_file = NULL;
    }

    if (tlog_filter.app_name) {
        free(tlog_filter.app_name);
        tlog_filter.app_name = NULL;
    }

    if (tlog_out_file && tlog_out_file != stdout) {
        fclose(tlog_out_file);
    }

    return ret;
}

/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <private/android_filesystem_config.h>
#include <private/canned_fs_config.h>

typedef struct {
    const char* path;
    unsigned uid;
    unsigned gid;
    unsigned mode;
    struct fs_capabilities capabilities;
} Path;

static Path* canned_data = NULL;
static int canned_alloc = 0;
static int canned_used = 0;

static int path_compare(const void* a, const void* b) {
    return strcmp(((Path*)a)->path, ((Path*)b)->path);
}

int load_canned_fs_config(const char* fn) {
    char line[PATH_MAX + 200];
    FILE* f;

    f = fopen(fn, "r");
    if (f == NULL) {
        fprintf(stderr, "failed to open %s: %s\n", fn, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), f)) {
        Path* p;
        char* token;

        while (canned_used >= canned_alloc) {
            canned_alloc = (canned_alloc+1) * 2;
            canned_data = (Path*) realloc(canned_data, canned_alloc * sizeof(Path));
        }
        p = canned_data + canned_used;
        p->path = strdup(strtok(line, " "));
        p->uid = atoi(strtok(NULL, " "));
        p->gid = atoi(strtok(NULL, " "));
        p->mode = strtol(strtok(NULL, " "), NULL, 8);   // mode is in octal
        memset(&(p->capabilities), 0, sizeof(p->capabilities));

        do {
            token = strtok(NULL, " ");
            if (token && strncmp(token, "capabilities=", 13) == 0) {
                p->capabilities.permitted = strtoll(token+13, NULL, 0);
                break;
            }
            if (token && strncmp(token, "cap.permitted=", 14) == 0) {
                p->capabilities.permitted = strtoll(token+14, NULL, 0);
            }
            else if (token && strncmp(token, "cap.inheritable=", 15) == 0) {
                p->capabilities.inheritable = strtoll(token+15, NULL, 0);
            }
        } while (token);

        canned_used++;
    }

    fclose(f);

    qsort(canned_data, canned_used, sizeof(Path), path_compare);
    printf("loaded %d fs_config entries\n", canned_used);

    return 0;
}

static const int kDebugCannedFsConfig = 0;

void canned_fs_config(const char* path, int dir, const char* target_out_path,
                      unsigned* uid, unsigned* gid, unsigned* mode, struct fs_capabilities *capabilities) {
    Path key, *p;

    key.path = path;
    if (path[0] == '/') key.path++; // canned paths lack the leading '/'
    p = (Path*) bsearch(&key, canned_data, canned_used, sizeof(Path), path_compare);
    if (p == NULL) {
        fprintf(stderr, "failed to find [%s] in canned fs_config\n", path);
        exit(1);
    }
    *uid = p->uid;
    *gid = p->gid;
    *mode = p->mode;
    *capabilities = p->capabilities;

    if (kDebugCannedFsConfig) {
        // for debugging, run the built-in fs_config and compare the results.

        unsigned c_uid, c_gid, c_mode;
        struct fs_capabilities c_capabilities;

        fs_config(path, dir, target_out_path, &c_uid, &c_gid, &c_mode, &c_capabilities);

        if (c_uid != *uid) printf("%s uid %d %d\n", path, *uid, c_uid);
        if (c_gid != *gid) printf("%s gid %d %d\n", path, *gid, c_gid);
        if (c_mode != *mode) printf("%s mode 0%o 0%o\n", path, *mode, c_mode);
        if (c_capabilities.permitted != capabilities->permitted
            || c_capabilities.inheritable != capabilities->inheritable) {
            printf("%s:\n\tcapabilities permitted: %" PRIx64 " %" PRIx64 "\n" \
		"\tcapabilities inheritable: %" PRIx64 " %" PRIx64 "\n",
                path,
                capabilities->permitted,
                c_capabilities.permitted,
                capabilities->inheritable,
                c_capabilities.inheritable);
        }
    }
}

/*
 * Copyright (C) 2015 The Android Open Source Project
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
#include <libgen.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cutils/log.h"
#include <cutils/klog.h>

#if defined(__BIONIC__)
#define FTW_CONTINUE 0
#else
// TODO - this is hacky. Elliott - help!?
#define __USE_GNU 1
#define __USE_XOPEN_EXTENDED 1
#endif
#include <ftw.h>

#define TAG "tzdatacheck"
#define ZONEINFO_FILENAME "/tzdata"

#define UNUSED __attribute__((unused))

void fatal(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(-1);
}

void usage() {
    fatal("Usage: tzdatacheck SYSTEM_TZ_DIR DATA_TZ_DIR\n"
            "\n"
            "Compares the header of two tzdata files. If the one in SYSTEM_TZ_DIR "
            "is a higher version than the one in DATA_TZ_DIR the DATA_TZ_DIR is renamed "
            "and deleted."
            );
}

char* concat(const char* one, const char* two) {
    size_t len = strlen(one) + strlen(two) + 1;
    char* output = (char*) malloc(len);
    if (!output) {
        fatal("Allocation error");
    }
    output[0] = '\0';
    strcat(output, one);
    strcat(output, two);
    return output;
}

/* Deletes a single file, symlink or directory. */
static int deleteFn(const char* fpath, const struct stat* sb UNUSED, int typeflag,
        struct FTW* ftwbuf UNUSED) {
    ALOG(LOG_DEBUG, TAG, "Inspecting %s", fpath);
    switch (typeflag) {
    case FTW_F:
    case FTW_SL:
        ALOG(LOG_DEBUG, TAG, "Unlinking %s", fpath);
        if (unlink(fpath)) {
            ALOG(LOG_WARN, TAG, "Failed to unlink file/symlink %s: %s", fpath, strerror(errno));
        }
        break;
    case FTW_D:
    case FTW_DP:
        ALOG(LOG_DEBUG, TAG, "Removing dir %s", fpath);
        if (rmdir(fpath)) {
            ALOG(LOG_WARN, TAG, "Failed to remove dir %s: %s", fpath, strerror(errno));
        }
        break;
    default:
        ALOG(LOG_WARN, TAG, "Unsupported file type %s: %d", fpath, typeflag);
        break;
    }
    return FTW_CONTINUE;
}

/* Returns 11 bytes from file, the first 6 of which will be "tzdata" */
char* readZoneInfoHeader(FILE* file, const char* name) {
    char* zoneInfoHeader = (char*)malloc(11);
    fread(zoneInfoHeader, 1, 11, file);
    if (strncmp("tzdata", zoneInfoHeader, 6)) {
        fatal("%s does not start with the expected bytes (%s)", name, "tzdata");
    }
    return zoneInfoHeader;
}

void deleteSafely(const char* dataTzDir) {
    // First, rename dataTzDir so we don't end up with a partially deleted data set.
    char* dataTzDirParent = (char*)malloc(strlen(dataTzDir) + 1);
    strcpy(dataTzDirParent, dataTzDir);
    dataTzDirParent = dirname(dataTzDirParent);

    // Create an empty directory with a unique name.
    char* oldFileTemplate = "/oldXXXXXX";
    char* oldTzDataDir = concat(dataTzDirParent, oldFileTemplate);
    if (!mkdtemp(oldTzDataDir)) {
        fatal("Unable to create a temporary directory to hold old tzdata: %s", oldTzDataDir);
    }
    rename(dataTzDir, oldTzDataDir);

    // Recursively delete contents of oldDataDir.
    if (nftw(oldTzDataDir, deleteFn, 10 /* openFiles */, FTW_DEPTH | FTW_MOUNT | FTW_PHYS)) {
        ALOG(LOG_INFO, TAG, "Could not delete old tz data directory %s.", oldTzDataDir);
    }

    free(dataTzDirParent);
    free(oldTzDataDir);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
    }

    char* systemTzDir = argv[1];
    char* dataTzDir = argv[2];

    struct stat buf;

    char* dataZoneInfo = concat(dataTzDir, ZONEINFO_FILENAME);
    FILE* dataZoneInfoFile = fopen(dataZoneInfo, "r");
    if (dataZoneInfoFile == NULL) {
        if (errno == ENOENT) {
            ALOG(LOG_INFO, TAG, "tzdata file %s does not exist or is unreadable. No action required.", dataZoneInfo);
            free(dataZoneInfo);
            exit(0);
      } else {
            fatal("Error opening tzdata file %s: %s (%d)", dataZoneInfo, strerror(errno), errno);
      }
    }

    char* systemZoneInfo = concat(systemTzDir, ZONEINFO_FILENAME);
    FILE* systemZoneInfoFile = fopen(systemZoneInfo, "r");
    if (systemZoneInfoFile == NULL) {
        fatal("%s does not exist or could not be opened", systemZoneInfo);
    }

    // File header (as much as we need):
    // byte[12] tzdata_version  -- "tzdata2012f\0
    char* systemZoneInfoHeader = readZoneInfoHeader(systemZoneInfoFile, systemZoneInfo);
    fclose(systemZoneInfoFile);

    char* dataZoneInfoHeader = readZoneInfoHeader(dataZoneInfoFile, dataZoneInfo);
    fclose(dataZoneInfoFile);

    if (strncmp(systemZoneInfoHeader, dataZoneInfoHeader, 11) <= 0) {
        ALOG(LOG_INFO, TAG, "tzdata file %s is the same or newer than %s. No action required.", dataZoneInfo, systemZoneInfo);
    } else {
        ALOG(LOG_INFO, TAG, "tzdata file %s is the older than %s. Removing it.", dataZoneInfo, systemZoneInfo);
        // The version in /data is lower than the version in /system. This could happen after an OTA.
        // We have to remove it or risk using stale tz data.
        deleteSafely(dataTzDir);
    }

    free(systemZoneInfoHeader);
    free(dataZoneInfoHeader);
    free(dataZoneInfo);
    free(systemZoneInfo);
    return 0;
}

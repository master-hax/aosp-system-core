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
#include <string>
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

static void fatal(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(-1);
}

static void usage() {
    fatal("Usage: tzdatacheck SYSTEM_TZ_DIR DATA_TZ_DIR\n"
            "\n"
            "Compares the header of two tzdata files. If the one in SYSTEM_TZ_DIR "
            "is the same or a higher version than the one in DATA_TZ_DIR the DATA_TZ_DIR is "
            "renamed and then deleted."
            );
}

/* Deletes a single file, symlink or directory. Called from nftw(). */
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

/*
 * Returns a new array containing the first 11 bytes from file, the first 6 of which will be
 * "tzdata".
 */
static char* readZoneInfoHeader(FILE* file, const std::string &name) {
    char* zoneInfoHeader = new char[11];
    if (!zoneInfoHeader) {
        fatal("Allocation error");
    }
    fread(zoneInfoHeader, 1, 11, file);
    if (strncmp("tzdata", zoneInfoHeader, 6)) {
        fatal("%s does not start with the expected bytes (%s)", name.c_str(), "tzdata");
    }
    return zoneInfoHeader;
}

/*
 * Populates parentDirName with the parent of dirName.
 */
static void getParentDir(const std::string &dirName, std::string &parentDirName) {
    char* parentDir = new char[dirName.length() + 1];
    if (!parentDir) {
        fatal("Allocation error");
    }
    strcpy(parentDir, dirName.c_str());
    parentDir = dirname(parentDir);
    parentDirName.assign(parentDir);
    delete[] parentDir;
}

/*
 * Deletes the contents of dataTzDir. This function first renames the directory to a temporary name.
 * If a temp directory cannot be created, or the directory renamed, this is consider a fatal error.
 * After the rename, deletion of files and subdirs beneath the directory is performed on a "best
 * effort" basis. Symlinks beneath the directory are not followed.
 */
static void deleteDir(const std::string &dataTzDir) {
    // First, rename dataTzDir so we don't end up with a partially deleted data set.
    std::string oldTzDataDirString;
    getParentDir(dataTzDir, oldTzDataDirString);
    oldTzDataDirString.append("/oldXXXXXX");

    // Create an empty directory with a unique name.
    char* oldTzDataDir = new char[oldTzDataDirString.length()];
    strcpy(oldTzDataDir, oldTzDataDirString.c_str());
    if (mkdtemp(oldTzDataDir) == NULL) {
        fatal("Unable to create a temporary directory to hold old tzdata: %s", oldTzDataDir);
    }
    int rc = rename(dataTzDir.c_str(), oldTzDataDir);
    if (rc != 0) {
        fatal("Unable to rename old tzdata directory from %s to %s",
                dataTzDir.c_str(), oldTzDataDir);
    }

    // Recursively delete contents of oldTzDataDir.
    rc = nftw(oldTzDataDir, deleteFn, 10 /* openFiles */, FTW_DEPTH | FTW_MOUNT | FTW_PHYS);
    if (rc != 0) {
        ALOG(LOG_INFO, TAG, "Could not delete old tz data directory %s.", oldTzDataDir);
    }
    delete[] oldTzDataDir;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
    }

    char* systemTzDir = argv[1];
    char* dataTzDir = argv[2];

    std::string dataZoneInfo(dataTzDir);
    dataZoneInfo.append(ZONEINFO_FILENAME);
    FILE* dataZoneInfoFile = fopen(dataZoneInfo.c_str(), "r");
    if (dataZoneInfoFile == NULL) {
        if (errno == ENOENT) {
            ALOG(LOG_INFO, TAG,
                    "tzdata file %s does not exist or is unreadable. No action required.",
                    dataZoneInfo.c_str());
            exit(0);
      } else {
            fatal("Error opening tzdata file %s: %s (%d)",
                    dataZoneInfo.c_str(), strerror(errno), errno);
      }
    }

    std::string systemZoneInfo(systemTzDir);
    systemZoneInfo.append(ZONEINFO_FILENAME);
    FILE* systemZoneInfoFile = fopen(systemZoneInfo.c_str(), "r");
    if (systemZoneInfoFile == NULL) {
        fatal("%s does not exist or could not be opened", systemZoneInfo.c_str());
    }

    // File header (as much as we need):
    // byte[12] tzdata_version  -- "tzdata2012f\0
    char* systemZoneInfoHeader = readZoneInfoHeader(systemZoneInfoFile, systemZoneInfo);
    fclose(systemZoneInfoFile);

    char* dataZoneInfoHeader = readZoneInfoHeader(dataZoneInfoFile, dataZoneInfo);
    fclose(dataZoneInfoFile);

    if (strncmp(systemZoneInfoHeader, dataZoneInfoHeader, 11) < 0) {
        ALOG(LOG_INFO, TAG, "tzdata file %s is the newer than %s. No action required.",
                dataZoneInfo.c_str(), systemZoneInfo.c_str());
    } else {
        ALOG(LOG_INFO, TAG, "tzdata file %s is the same or older than %s. Removing it.",
                dataZoneInfo.c_str(), systemZoneInfo.c_str());
        // This situation can exist after an OTA. We have to remove the /data files or risk using
        // stale tz data.
        deleteDir(dataTzDir);
    }

    delete[] systemZoneInfoHeader;
    delete[] dataZoneInfoHeader;
    return 0;
}

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
#include <array>
#include <memory>
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
#define TZDATA_FILENAME "/tzdata"

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

/*
 * Returns an array containing the first 11 bytes from file, the first 6 of which will be
 * "tzdata". It is a fatal error if the header does not start with the expected bytes.
 */
static std::array<char, 11> readZoneInfoHeader(FILE* file, const std::string &name) {
    std::array<char, 11> zoneInfoHeader;
    fread(zoneInfoHeader.data(), 1, 11, file);
    if (strncmp("tzdata", zoneInfoHeader.data(), 6)) {
        fatal("%s does not start with the expected bytes (%s)", name.c_str(), "tzdata");
    }
    return zoneInfoHeader;
}

/*
 * Populates parentDirName with the parent of dirName.
 */
static void getParentDir(const std::string &dirName, std::string &parentDirName) {
    char* parentDir = new char[dirName.length() + 1];
    strcpy(parentDir, dirName.c_str());
    parentDir = dirname(parentDir);
    parentDirName.assign(parentDir);
    delete[] parentDir;
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
 * Deletes dirToDelete and returns value indicating whether it was entirely successful. If
 * dirToDelete does not exist this function does nothing and returns 0. If dirToDelete is not a
 * directory or cannot be read it returns -2.
 * During deletion, this function first renames the directory to a temporary name. If the temporary
 * directory cannot be created, or the directory cannot be renamed, -1 is returned.
 * After the rename, deletion of files and subdirs beneath the directory is performed on a "best
 * effort" basis. Symlinks beneath the directory are not followed. If the deletion was entirely
 * successful then 0 is returned. 1 is returned if the temporary directory may still exist.
 *
 * In summary:
 * A negative result means something bad happened: either the file system was not as
 * expected or there were unexpected I/O issues.
 * A zero result means no action was required or the deletion was full successful.
 * A positive result means that it wasn't entirely successful, but should be "good enough" (i.e.
 * dirToDelete no longer exists in its original location).

 */
static int deleteDir(const std::string &dirToDelete) {
    // Check whether the dir exists.
    struct stat buf;
    if (stat(dirToDelete.c_str(), &buf) == 0) {
      if (!S_ISDIR(buf.st_mode)) {
        ALOG(LOG_WARN, TAG, "%s is not a directory", dirToDelete.c_str());
        return -2;
      }
    } else {
      if (errno == ENOENT) {
          ALOG(LOG_INFO, TAG, "Directory does not exist: %s", dirToDelete.c_str());
          return 0;
      } else {
          ALOG(LOG_WARN, TAG, "Unable to stat %s: %s", dirToDelete.c_str(), strerror(errno));
          return -2;
      }
    }

    // First, rename dirToDelete.
    std::string tempDirNameTemplate;
    getParentDir(dirToDelete, tempDirNameTemplate);
    tempDirNameTemplate.append("/tempXXXXXX");

    // Create an empty directory with the temporary name. For this we need a non-const char*.
    std::unique_ptr<char> tempDirName(new char[tempDirNameTemplate.length() + 1]);
    strcpy(tempDirName.get(), tempDirNameTemplate.c_str());
    if (mkdtemp(tempDirName.get()) == NULL) {
        ALOG(LOG_WARN, TAG, "Unable to create a temporary directory: %s",
                tempDirNameTemplate.c_str());
        return -1;
    }

    // Rename dirToDelete to tempDirName.
    int rc = rename(dirToDelete.c_str(), tempDirName.get());
    if (rc != 0) {
        ALOG(LOG_WARN, TAG, "Unable to rename directory from %s to %s",
                dirToDelete.c_str(), tempDirName.get());
        return -1;
    }

    // Recursively delete contents of tempDirName.
    rc = nftw(tempDirName.get(), deleteFn, 10 /* openFiles */, FTW_DEPTH | FTW_MOUNT | FTW_PHYS);
    if (rc != 0) {
        ALOG(LOG_INFO, TAG, "Could not delete directory: %s", tempDirName.get());
    }
    return rc == 0 ? 0 : 1;
}

/*
 * After a platform update it is likely that timezone data found on the system partition will be
 * newer than the version found in the data partition. This tool detects this case and removes the
 * version in /data along with any update metadata.
 *
 * Note: This code is related to code in com.android.server.updates.TzDataInstallReceiver. The
 * paths for the metadata and current timezone data must match.
 *
 * Typically on device the two args will be:
 *   /system/usr/share/zoneinfo /data/misc/zoneinfo
 *
 * See usage() for usage notes.
 */
int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
    }

    char* systemZoneInfoDir = argv[1];
    char* dataZoneInfoDir = argv[2];

    std::string dataCurrentDirName(dataZoneInfoDir);
    dataCurrentDirName.append("/current");

    std::string dataTzDataFileName(dataCurrentDirName);
    dataTzDataFileName.append(TZDATA_FILENAME);
    FILE* dataTzDataFile = fopen(dataTzDataFileName.c_str(), "r");
    if (dataTzDataFile == NULL) {
        if (errno == ENOENT) {
            ALOG(LOG_INFO, TAG,
                    "tzdata file %s does not exist or is unreadable. No action required.",
                    dataTzDataFileName.c_str());
            exit(0);
      } else {
            fatal("Error opening tzdata file %s: %s (%d)",
                    dataTzDataFileName.c_str(), strerror(errno), errno);
      }
    }

    std::string systemTzDataFileName(systemZoneInfoDir);
    systemTzDataFileName.append(TZDATA_FILENAME);
    FILE* systemTzDataFile = fopen(systemTzDataFileName.c_str(), "r");
    if (systemTzDataFile == NULL) {
        fatal("%s does not exist or could not be opened", systemTzDataFileName.c_str());
    }

    // File header (as much as we need):
    // byte[12] tzdata_version  -- "tzdata2012f\0
    std::array<char, 11> systemTzDataHeader =
            readZoneInfoHeader(systemTzDataFile, systemTzDataFileName);
    fclose(systemTzDataFile);

    std::array<char, 11> dataTzDataHeader =
            readZoneInfoHeader(dataTzDataFile, dataTzDataFileName);
    fclose(dataTzDataFile);

    if (strncmp(systemTzDataHeader.data(), dataTzDataHeader.data(), 11) < 0) {
        ALOG(LOG_INFO, TAG, "tzdata file %s is the newer than %s. No action required.",
                dataTzDataFileName.c_str(), systemTzDataFileName.c_str());
    } else {
        // We have detected the case this tools is intended to prevent. Go fix it.
        ALOG(LOG_INFO, TAG, "tzdata file %s is the same or older than %s",
                dataTzDataFileName.c_str(), systemTzDataFileName.c_str());

        // We delete the update metadata then the tz data. The combinations of the operations is
        // not atomic but we try our best to do both even when things are not quite what we expect.

        // Delete the update metadata
        std::string dataUpdatesDirName(dataZoneInfoDir);
        dataUpdatesDirName.append("/updates");
        ALOG(LOG_INFO, TAG, "Removing: %s", dataUpdatesDirName.c_str());
        int rc = deleteDir(dataUpdatesDirName);
        if (rc != 0) {
            ALOG(LOG_WARN, TAG, "Deletion of install metadata %s was not successful: %d",
                    dataUpdatesDirName.c_str(), rc);
        }

        // Delete the TZ data
        ALOG(LOG_INFO, TAG, "Removing: %s", dataCurrentDirName.c_str());
        rc = deleteDir(dataCurrentDirName);
        if (rc != 0) {
            ALOG(LOG_WARN, TAG, "Deletion of tzdata %s was not successful: %d",
                    dataCurrentDirName.c_str(), rc);
        }
    }

    return 0;
}

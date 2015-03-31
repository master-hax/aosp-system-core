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
#include <ftw.h>
#include <libgen.h>
#include <memory>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <unistd.h>
#include <vector>

#include "base/logging.h"

static const std::string TZDATA_FILENAME = "/tzdata";

static void usage() {
    LOG(FATAL) << "Usage: tzdatacheck SYSTEM_TZ_DIR DATA_TZ_DIR\n"
            "\n"
            "Compares the header of two tzdata files. If the one in SYSTEM_TZ_DIR "
            "is the same or a higher version than the one in DATA_TZ_DIR the DATA_TZ_DIR is "
            "renamed and then deleted.";
}

/*
 * Returns a vector containing the first 11 bytes from file, the first 6 of which will be
 * "tzdata". It is a fatal error if the header does not start with the expected bytes.
 */
static std::vector<char> readZoneInfoHeader(FILE* file, const std::string& name) {
    std::vector<char> zoneInfoHeader(11);
    fread(&zoneInfoHeader[0], 1, 11, file);
    if (strncmp("tzdata", &zoneInfoHeader[0], 6)) {
        LOG(FATAL) << name << " does not start with the expected bytes (tzdata)";
    }
    return zoneInfoHeader;
}

/*
 * Populates parentDirName with the parent of dirName.
 */
static std::string getParentDir(const std::string& dirName) {
    std::vector<char> dirNameCopy(dirName.length() + 1);
    strcpy(&dirNameCopy[0], dirName.c_str());
    char* parentDir = dirname(&dirNameCopy[0]);
    std::string parentDirName(parentDir);
    return parentDirName;
}

/* Deletes a single file, symlink or directory. Called from nftw(). */
static int deleteFn(const char* fpath, const struct stat*, int typeflag, struct FTW*) {
    LOG(DEBUG) << "Inspecting " << fpath;
    switch (typeflag) {
    case FTW_F:
    case FTW_SL:
        LOG(DEBUG) << "Unlinking " << fpath;
        if (unlink(fpath)) {
            LOG(WARNING) << "Failed to unlink file/symlink " << fpath << ": " << strerror(errno);
        }
        break;
    case FTW_D:
    case FTW_DP:
        LOG(DEBUG) << "Removing dir " << fpath;
        if (rmdir(fpath)) {
            LOG(WARNING) << "Failed to remove dir " << fpath << ": " << strerror(errno);
        }
        break;
    default:
        LOG(WARNING) << "Unsupported file type " << fpath << ": " << typeflag;
        break;
    }
    return 0;
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
static int deleteDir(const std::string& dirToDelete) {
    // Check whether the dir exists.
    struct stat buf;
    if (stat(dirToDelete.c_str(), &buf) == 0) {
      if (!S_ISDIR(buf.st_mode)) {
        LOG(WARNING) << dirToDelete << " is not a directory";
        return -2;
      }
    } else {
      if (errno == ENOENT) {
          LOG(INFO) << "Directory does not exist: " << dirToDelete;
          return 0;
      } else {
          LOG(WARNING) << "Unable to stat " << dirToDelete << ": " << strerror(errno);
          return -2;
      }
    }

    // First, rename dirToDelete.
    std::string tempDirNameTemplate = getParentDir(dirToDelete);
    tempDirNameTemplate.append("/tempXXXXXX");

    // Create an empty directory with the temporary name. For this we need a non-const char*.
    std::vector<char> tempDirName(tempDirNameTemplate.length() + 1);
    strcpy(&tempDirName[0], tempDirNameTemplate.c_str());
    if (mkdtemp(&tempDirName[0]) == NULL) {
        LOG(WARNING) << "Unable to create a temporary directory: " << tempDirNameTemplate;
        return -1;
    }
    std::string tempDirNameString(&tempDirName[0]);

    // Rename dirToDelete to tempDirName.
    int rc = rename(dirToDelete.c_str(), tempDirNameString.c_str());
    if (rc != 0) {
        LOG(WARNING) << "Unable to rename directory from " << dirToDelete << " to "
                << tempDirNameString;
        return -1;
    }

    // Recursively delete contents of tempDirName.
    rc = nftw(tempDirNameString.c_str(), deleteFn, 10 /* openFiles */,
            FTW_DEPTH | FTW_MOUNT | FTW_PHYS);
    if (rc != 0) {
        LOG(INFO) << "Could not delete directory: " << tempDirNameString;
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

    const char* systemZoneInfoDir = argv[1];
    const char* dataZoneInfoDir = argv[2];

    std::string dataCurrentDirName(dataZoneInfoDir);
    dataCurrentDirName.append("/current");

    std::string dataTzDataFileName(dataCurrentDirName);
    dataTzDataFileName.append(TZDATA_FILENAME);
    FILE* dataTzDataFile = fopen(dataTzDataFileName.c_str(), "r");
    if (dataTzDataFile == NULL) {
        if (errno == ENOENT) {
            LOG(INFO) << "tzdata file " << dataTzDataFileName
                    << " does not exist or is unreadable. No action required.";
            return 0;
      } else {
          LOG(FATAL) << "Error opening tzdata file " << dataTzDataFileName << ": "
                  << strerror(errno) << "(" << errno << ")";
      }
    }

    std::string systemTzDataFileName(systemZoneInfoDir);
    systemTzDataFileName.append(TZDATA_FILENAME);
    FILE* systemTzDataFile = fopen(systemTzDataFileName.c_str(), "r");
    if (systemTzDataFile == NULL) {
        LOG(FATAL) << systemTzDataFileName << " does not exist or could not be opened";
    }

    // File header (as much as we need):
    // byte[12] tzdata_version  -- "tzdata2012f\0
    std::vector<char> systemTzDataHeader =
            readZoneInfoHeader(systemTzDataFile, systemTzDataFileName);
    fclose(systemTzDataFile);

    std::vector<char> dataTzDataHeader =
            readZoneInfoHeader(dataTzDataFile, dataTzDataFileName);
    fclose(dataTzDataFile);

    if (strncmp(&systemTzDataHeader[0], &dataTzDataHeader[0], 11) < 0) {
        LOG(INFO) << "tzdata file " << dataTzDataFileName << " is the newer than "
                << systemTzDataFileName << ". No action required.";
    } else {
        // We have detected the case this tool is intended to prevent. Go fix it.
        LOG(INFO) << "tzdata file " << dataTzDataFileName << " is the same or older than "
                << systemTzDataFileName;

        // Delete the update metadata
        std::string dataUpdatesDirName(dataZoneInfoDir);
        dataUpdatesDirName.append("/updates");
        LOG(INFO) << "Removing: " << dataUpdatesDirName;
        int rc = deleteDir(dataUpdatesDirName);
        if (rc != 0) {
            LOG(WARNING) << "Deletion of install metadata " << dataUpdatesDirName
                    << " was not successful: " << rc;
        }

        // Delete the TZ data
        LOG(INFO) << "Removing: " << dataCurrentDirName;
        rc = deleteDir(dataCurrentDirName);
        if (rc != 0) {
            LOG(WARNING) << "Deletion of tzdata " << dataCurrentDirName << " was not successful: "
                    << rc;
        }
    }

    return 0;
}

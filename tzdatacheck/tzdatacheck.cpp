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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "android-base/logging.h"

static const char* BUNDLE_VERSION_FILENAME = "/bundle_version";
// bundle_version is a file consisting of 3 bytes representing the version in ASCII. e.g. 001.
static const int BUNDLE_VERSION_LENGTH = 3;
// The version of the bundle format supported. If it doesn't match the content of the bundle_version
// file exactly then the bundle is considered incompatible and should be deleted.
static const char* REQUIRED_BUNDLE_VERSION = "001";

static const char* TZDATA_FILENAME = "/tzdata";
// tzdata file header (as much as we need for the version):
// byte[11] tzdata_version  -- e.g. "tzdata2012f"
static const int TZ_HEADER_LENGTH = 11;

static void usage() {
    std::cerr << "Usage: tzdatacheck SYSTEM_TZ_DIR DATA_TZ_DIR\n"
            "\n"
            "Checks whether any timezone update bundle in DATA_TZ_DIR is compatible with the\n"
            "current Android release and better than or the same as base system timezone rules in\n"
            "SYSTEM_TZ_DIR. If the timezone rules in SYSTEM_TZ_DIR are a higher version than the\n"
            "one in DATA_TZ_DIR the DATA_TZ_DIR is renamed and then deleted.\n";
    exit(1);
}

/*
 * Opens a file and fills buffer with the first byteCount bytes from the file.
 * If the file does not exist or cannot be opened or is too short then false is returned.
 * If the bytes were read successfully then true is returned.
 */
static bool readBytes(const std::string& fileName, char* buffer, size_t byteCount) {
    FILE* file = fopen(fileName.c_str(), "r");
    if (file == nullptr) {
        if (errno != ENOENT) {
            PLOG(WARNING) << "Error opening file " << fileName;
        }
        return false;
    }
    size_t bytesRead = fread(buffer, 1, byteCount, file);
    fclose(file);
    if (bytesRead != byteCount) {
        LOG(WARNING) << fileName << " is too small. " << byteCount << " bytes required";
        return false;
    }
    return true;
}

/*
 * Checks the contents of headerBytes. Returns true if it is valid (starts with "tzdata"), false
 * otherwise.
 */
static bool checkValidTzDataHeader(const std::string& fileName, char* headerBytes) {
    if (strncmp("tzdata", headerBytes, 6) != 0) {
        LOG(WARNING) << fileName << " does not start with the expected bytes (tzdata)";
        return false;
    }
    return true;
}

/* Return the parent directory of dirName. */
static std::string getParentDir(const std::string& dirName) {
    std::unique_ptr<char> mutable_dirname(strdup(dirName.c_str()));
    return dirname(mutable_dirname.get());
}

/* Deletes a single file, symlink or directory. Called from nftw(). */
static int deleteFn(const char* fpath, const struct stat*, int typeflag, struct FTW*) {
    LOG(DEBUG) << "Inspecting " << fpath;
    switch (typeflag) {
    case FTW_F:
    case FTW_SL:
        LOG(DEBUG) << "Unlinking " << fpath;
        if (unlink(fpath)) {
            PLOG(WARNING) << "Failed to unlink file/symlink " << fpath;
        }
        break;
    case FTW_D:
    case FTW_DP:
        LOG(DEBUG) << "Removing dir " << fpath;
        if (rmdir(fpath)) {
            PLOG(WARNING) << "Failed to remove dir " << fpath;
        }
        break;
    default:
        LOG(WARNING) << "Unsupported file type " << fpath << ": " << typeflag;
        break;
    }
    return 0;
}

static bool dirExists(const std::string& dirName) {
    struct stat buf;
    if (stat(dirName.c_str(), &buf) == 0) {
        if (!S_ISDIR(buf.st_mode)) {
            PLOG(WARNING) << dirName << " exists but is not a directory";
        }
        return true;
    } else {
      if (errno != ENOENT) {
          PLOG(WARNING) << "Unable to stat " << dirName;
      }
      return false;
    }
}

/*
 * Deletes dirToDelete and returns true if it is successful in removing or moving the directory out
 * of the way. If dirToDelete does not exist this function does nothing and returns true.
 *
 * During deletion, this function first renames the directory to a temporary name. If the temporary
 * directory cannot be created, or the directory cannot be renamed, false is returned. After the
 * rename, deletion of files and subdirs beneath the directory is performed on a "best effort"
 * basis. Symlinks beneath the directory are not followed.
 */
static bool deleteDir(const std::string& dirToDelete) {
    // Check whether the dir exists.
    if (!dirExists(dirToDelete)) {
        LOG(INFO) << "Directory does not exist: " << dirToDelete;
        return false;
    }

    // First, rename dirToDelete.
    std::string tempDirNameTemplate = getParentDir(dirToDelete);
    tempDirNameTemplate += "/tempXXXXXX";

    // Create an empty directory with the temporary name. For this we need a non-const char*.
    std::vector<char> tempDirName(tempDirNameTemplate.length() + 1);
    strcpy(&tempDirName[0], tempDirNameTemplate.c_str());
    if (mkdtemp(&tempDirName[0]) == nullptr) {
        PLOG(WARNING) << "Unable to create a temporary directory: " << tempDirNameTemplate;
        return false;
    }

    // Rename dirToDelete to tempDirName.
    int rc = rename(dirToDelete.c_str(), &tempDirName[0]);
    if (rc == -1) {
        PLOG(WARNING) << "Unable to rename directory from " << dirToDelete << " to "
                << &tempDirName[0];
        return false;
    }

    // Recursively delete contents of tempDirName.
    rc = nftw(&tempDirName[0], deleteFn, 10 /* openFiles */,
            FTW_DEPTH | FTW_MOUNT | FTW_PHYS);
    if (rc == -1) {
        LOG(INFO) << "Could not delete directory: " << &tempDirName[0];
    }
    return true;
}

/*
 * Deletes the timezone update bundle directory.
 */
static void deleteUpdateBundleDir(std::string& bundleDirName) {
    LOG(INFO) << "Removing: " << bundleDirName;
    bool deleted = deleteDir(bundleDirName);
    if (!deleted) {
        LOG(WARNING) << "Deletion of bundle dir " << bundleDirName << " was not successful";
    }
}

/*
 * After a platform update it is likely that timezone data found on the system partition will be
 * newer than the version found in the data partition. This tool detects this case and removes the
 * version in /data.
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

    // Check the bundle directory exists. If it does not, exit quickly.
    std::string dataCurrentDirName(dataZoneInfoDir);
    dataCurrentDirName += "/current";
    if (!dirExists(dataCurrentDirName)) {
        LOG(INFO) << "timezone bundle dir " << dataCurrentDirName
                << " does not exist. No action required.";
        return 0;
    }

    // Check the installed bundle format version.
    std::string bundleVersionFileName(dataCurrentDirName);
    bundleVersionFileName += BUNDLE_VERSION_FILENAME;
    std::vector<char> bundleVersionHeader;
    bundleVersionHeader.reserve(BUNDLE_VERSION_LENGTH);
    bool bundleVersionFileExists =
            readBytes(bundleVersionFileName, bundleVersionHeader.data(), BUNDLE_VERSION_LENGTH);
    if (!bundleVersionFileExists) {
        LOG(WARNING) << "bundle version file " << bundleVersionFileName
                << " does not exist. Deleting bundle dir.";
        deleteUpdateBundleDir(dataCurrentDirName);
        return 0;
    }
    if (strncmp(&bundleVersionHeader[0], REQUIRED_BUNDLE_VERSION, BUNDLE_VERSION_LENGTH) != 0) {
        LOG(INFO) << "bundle version file " << bundleVersionFileName
                << " is not the required version " << REQUIRED_BUNDLE_VERSION
                << ". Deleting bundle dir..";
        deleteUpdateBundleDir(dataCurrentDirName);
        return 0;
    }

    // Now check the IANA rules version the data is for.
    std::string dataTzDataFileName(dataCurrentDirName);
    dataTzDataFileName += TZDATA_FILENAME;
    std::vector<char> dataTzDataHeader;
    dataTzDataHeader.reserve(TZ_HEADER_LENGTH);
    bool dataFileExists = readBytes(dataTzDataFileName, dataTzDataHeader.data(), TZ_HEADER_LENGTH);
    if (!dataFileExists) {
        LOG(WARNING) << "tzdata file " << dataTzDataFileName
                << " does not exist. Deleting bundle dir.";
        // For safety, delete the update bundle.
        deleteUpdateBundleDir(dataCurrentDirName);
        return 0;
    }
    if (!checkValidTzDataHeader(dataTzDataFileName, dataTzDataHeader.data())) {
        LOG(WARNING) << "tzdata file " << dataTzDataFileName
                << " does not have a valid header. Deleting bundle dir.";
        deleteUpdateBundleDir(dataCurrentDirName);
        return 0;
    }

    std::string systemTzDataFileName(systemZoneInfoDir);
    systemTzDataFileName += TZDATA_FILENAME;
    std::vector<char> systemTzDataHeader;
    systemTzDataHeader.reserve(TZ_HEADER_LENGTH);
    bool systemFileExists =
            readBytes(systemTzDataFileName, systemTzDataHeader.data(), TZ_HEADER_LENGTH);
    if (!systemFileExists) {
        LOG(FATAL) << systemTzDataFileName << " does not exist or could not be opened";
    }
    if (!checkValidTzDataHeader(systemTzDataFileName, systemTzDataHeader.data())) {
        // Nothing we can do here. Something has gone very wrong.
        LOG(FATAL) << systemTzDataFileName << " does not have a valid header.";
    }

    if (strncmp(&systemTzDataHeader[0], &dataTzDataHeader[0], TZ_HEADER_LENGTH) <= 0) {
        LOG(INFO) << "tzdata file " << dataTzDataFileName << " is the newer than or the same as "
                << systemTzDataFileName << ". No action required.";
        return 0;
    }

    // We have detected the case this tool is intended to prevent. Go fix it.
    LOG(INFO) << "tzdata file " << dataTzDataFileName << " is older than "
            << systemTzDataFileName << "; fixing...";

    deleteUpdateBundleDir(dataCurrentDirName);
    return 0;
}

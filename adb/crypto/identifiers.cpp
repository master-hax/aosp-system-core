/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
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

#include "identifiers.h"

#include "adb_utils.h"
#include "sysdeps.h"

#include <android-base/logging.h>
#include <memory>
#include <random>

static const char kDeviceIdFilename[] = "adb_deviceid";
static char kDeviceId[128] = { 0 };

// The amount of space reserved for the random part and the name part of the
// device ID.
static constexpr size_t kDeviceIdRandomSize = 64;
static constexpr size_t kDeviceIdNameSize = sizeof(kDeviceId) -
                                            kDeviceIdRandomSize - 2;

#if ADB_HOST
static std::string getDeviceIdPath() {
    return adb_get_android_dir_path() + OS_PATH_SEPARATOR + kDeviceIdFilename;
}
#else
static std::string getDeviceIdPath() {
    return std::string("/data/misc/adb/") + kDeviceIdFilename;
}
#endif

std::string get_hostname() {
    std::string hostname;

    const char* hostnamePtr = getenv("HOSTNAME");
    if (hostnamePtr && *hostnamePtr != '\0') {
        hostname = hostnamePtr;
    } else {
        char buffer[1024];
        if (adb_gethostname(buffer, sizeof(buffer)) == 0) {
            hostname = buffer;
        } else {
            hostname = "unknown";
        }
    }
    return hostname;
}

std::string get_username() {
    std::string username;

    const char* loginPtr = getenv("LOGNAME");
    if (loginPtr && *loginPtr != '\0') {
        username = loginPtr;
    } else {
        char buffer[1024];
        if (adb_getlogin_r(buffer, sizeof(buffer)) == 0) {
            username = buffer;
        } else {
            username = "unknown";
        }
    }
    return username;
}

std::string get_device_name() {
    return get_username() + "@" + get_hostname();
}

std::string get_unique_device_id() {
    // Check if we have cached the ID yet
    if (kDeviceId[0] != '\0') {
        LOG(ERROR) << "Returning cached device id";
        return kDeviceId;
    }
    LOG(ERROR) << "No cached device id";

    // If we haven't cached it attempt to open the file that contains the ID
    std::string path = getDeviceIdPath();
    std::unique_ptr<FILE, decltype(&fclose)> file(fopen(path.c_str(), "r"),
                                                  &fclose);
    if (file) {
        size_t bytes = fread(kDeviceId, 1, sizeof(kDeviceId), file.get());
        if (!ferror(file.get())) {
            kDeviceId[std::min(bytes, sizeof(kDeviceId) - 1)] = '\0';
            LOG(ERROR) << "Found device id on disk '" << kDeviceId << "'";
            return kDeviceId;
        }
    }
    LOG(ERROR) << "No device id on disk, generating";

    // If we haven't stored it we need to generate an ID
    std::string hostname = get_hostname();
    strncpy(kDeviceId, hostname.c_str(), kDeviceIdNameSize);
    kDeviceId[kDeviceIdNameSize] = '\0';
    strcat(kDeviceId, "-");

    char randomPart[kDeviceIdRandomSize];
    std::random_device rd;
    std::mt19937 mt(rd());
    // Generate values starting with zero and then up to enough to cover numeric
    // digits, small letters and capital letters (26 each).
    std::uniform_int_distribution<uint8_t> dist(0, 61);

    for (size_t i = 0; i < sizeof(randomPart) - 1; ++i) {
        uint8_t value = dist(mt);
        if (value < 10) {
            randomPart[i] = '0' + value;
        } else if (value < 36) {
            randomPart[i] = 'A' + (value - 10);
        } else {
            randomPart[i] = 'a' + (value - 36);
        }
    }
    randomPart[sizeof(randomPart) - 1] = '\0';

    strcat(kDeviceId, randomPart);

    file.reset(fopen(getDeviceIdPath().c_str(), "w"));
    if (file) {
        if (fwrite(kDeviceId, strlen(kDeviceId), 1, file.get()) != 1) {
            // Unable to write, return the ID for now but it will not persist
            // across boots.
            LOG(ERROR) << "Unable to store device ID: " << strerror(errno);
            kDeviceId[0] = '\0';
        }
    } else {
        LOG(ERROR) << "Unable to open device ID file for writing: " << strerror(errno);
        kDeviceId[0] = '\0';
    }
    return kDeviceId;
}



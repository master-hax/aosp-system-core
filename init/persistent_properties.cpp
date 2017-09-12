/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "persistent_properties.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/types.h>

#include <memory>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include "util.h"

using android::base::ReadFdToString;
using android::base::StartsWith;
using android::base::WriteStringToFd;
using android::base::unique_fd;

namespace android {
namespace init {

std::string persistent_property_filename = "/data/property/persistent_properties";

namespace {

constexpr const uint32_t kMagic = 0x8495E0B4;
constexpr const char kLegacyPersistentPropertyDir[] = "/data/property";

Result<std::vector<std::pair<std::string, std::string>>> LoadLegacyPersistentProperties() {
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(kLegacyPersistentPropertyDir), closedir);
    if (!dir) {
        return ErrnoError() << "Unable to open persistent property directory \""
                            << kLegacyPersistentPropertyDir << "\"";
    }

    std::vector<std::pair<std::string, std::string>> persistent_properties;
    dirent* entry;
    while ((entry = readdir(dir.get())) != nullptr) {
        if (!StartsWith(entry->d_name, "persist.")) {
            continue;
        }
        if (entry->d_type != DT_REG) {
            continue;
        }

        unique_fd fd(openat(dirfd(dir.get()), entry->d_name, O_RDONLY | O_NOFOLLOW));
        if (fd == -1) {
            PLOG(ERROR) << "Unable to open persistent property file \"" << entry->d_name << "\"";
            continue;
        }

        struct stat sb;
        if (fstat(fd, &sb) == -1) {
            PLOG(ERROR) << "fstat on property file \"" << entry->d_name << "\" failed";
            continue;
        }

        // File must not be accessible to others, be owned by root/root, and
        // not be a hard link to any other file.
        if (((sb.st_mode & (S_IRWXG | S_IRWXO)) != 0) || sb.st_uid != 0 || sb.st_gid != 0 ||
            sb.st_nlink != 1) {
            PLOG(ERROR) << "skipping insecure property file " << entry->d_name
                        << " (uid=" << sb.st_uid << " gid=" << sb.st_gid << " nlink=" << sb.st_nlink
                        << " mode=" << std::oct << sb.st_mode << ")";
            continue;
        }

        std::string value;
        if (ReadFdToString(fd, &value)) {
            persistent_properties.emplace_back(entry->d_name, value);
        } else {
            PLOG(ERROR) << "Unable to read persistent property file " << entry->d_name;
        }
    }
    return persistent_properties;
}

void RemoveLegacyPersistentPropertyFiles() {
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(kLegacyPersistentPropertyDir), closedir);
    if (!dir) {
        PLOG(ERROR) << "Unable to open persistent property directory \""
                    << kLegacyPersistentPropertyDir << "\"";
        return;
    }

    dirent* entry;
    while ((entry = readdir(dir.get())) != nullptr) {
        if (!StartsWith(entry->d_name, "persist.")) {
            continue;
        }
        if (entry->d_type != DT_REG) {
            continue;
        }
        unlinkat(dirfd(dir.get()), entry->d_name, 0);
    }
}

std::vector<std::pair<std::string, std::string>> LoadPersistentPropertiesFromMemory() {
    std::vector<std::pair<std::string, std::string>> properties;
    __system_property_foreach(
        [](const prop_info* pi, void* cookie) {
            __system_property_read_callback(
                pi,
                [](void* cookie, const char* name, const char* value, unsigned serial) {
                    if (StartsWith(name, "persist.")) {
                        auto properties =
                            reinterpret_cast<std::vector<std::pair<std::string, std::string>>*>(
                                cookie);
                        properties->emplace_back(name, value);
                    }
                },
                cookie);
        },
        &properties);
    return properties;
}

Result<std::vector<std::pair<std::string, std::string>>> ParsePersistentPropertyFile(
    const std::string& contents) {
    auto deserializer = Deserializer(contents);
    std::vector<std::pair<std::string, std::string>> result;

    if (auto magic = deserializer.ReadUint32(); magic) {
        if (*magic != kMagic) {
            return Error() << "Magic value '0x" << std::hex << *magic
                           << "' does not match expected value '0x" << kMagic << "'";
        }
    } else {
        return Error() << "Could not read magic value: " << magic.error();
    }

    if (auto version = deserializer.ReadUint32(); version) {
        if (*version != 1) {
            return Error() << "Version '" << *version
                           << "' does not match any compatible version: (1)";
        }
    } else {
        return Error() << "Could not read version: " << version.error();
    }

    auto num_properties = deserializer.ReadUint32();
    if (!num_properties) {
        return Error() << "Could not read num_properties: " << num_properties.error();
    }

    while (result.size() != *num_properties) {
        auto key = deserializer.ReadString();
        if (!key) {
            return Error() << "Could not read key: " << key.error();
        }
        if (!StartsWith(*key, "persist.")) {
            return Error() << "Property '" << *key << "' does not starts with 'persist.'";
        }
        auto value = deserializer.ReadString();
        if (!value) {
            return Error() << "Could not read value: " << value.error();
        }
        result.emplace_back(*key, *value);
    }

    if (result.size() != *num_properties) {
        return Error() << "Mismatch of number of persistent properties read, " << result.size()
                       << " and number of persistent properties expected, " << *num_properties;
    }

    return result;
}

}  // namespace

Result<std::vector<std::pair<std::string, std::string>>> LoadPersistentPropertyFile() {
    const std::string temp_filename = persistent_property_filename + ".tmp";
    if (access(temp_filename.c_str(), F_OK) == 0) {
        LOG(INFO)
            << "Found temporary property file while attempting to persistent system properties"
               " a previous persistent property write may have failed";
        unlink(temp_filename.c_str());
    }
    auto file_contents = ReadFile(persistent_property_filename);
    if (!file_contents) {
        return Error() << "Unable to read persistent property file: " << file_contents.error();
    }
    auto parsed_contents = ParsePersistentPropertyFile(*file_contents);
    if (!parsed_contents) {
        // If the file cannot be parsed, then we don't have any recovery mechanisms, so we delete
        // it to allow for future writes to take place successfully.
        unlink(persistent_property_filename.c_str());
        return Error() << "Unable to parse persistent property file: " << parsed_contents.error();
    }
    return parsed_contents;
}

std::string GenerateFileContents(
    const std::vector<std::pair<std::string, std::string>>& persistent_properties) {
    auto serializer = Serializer();

    serializer.WriteUint32(kMagic);
    serializer.WriteUint32(1);  // Version
    serializer.WriteUint32(persistent_properties.size());

    for (const auto& [key, value] : persistent_properties) {
        serializer.WriteString(key);
        serializer.WriteString(value);
    }
    return serializer.contents();
}

Result<Success> WritePersistentPropertyFile(
    const std::vector<std::pair<std::string, std::string>>& persistent_properties) {
    auto file_contents = GenerateFileContents(persistent_properties);

    const std::string temp_filename = persistent_property_filename + ".tmp";
    unique_fd fd(TEMP_FAILURE_RETRY(
        open(temp_filename.c_str(), O_WRONLY | O_CREAT | O_NOFOLLOW | O_TRUNC | O_CLOEXEC, 0600)));
    if (fd == -1) {
        return ErrnoError() << "Could not open temporary properties file";
    }
    if (!WriteStringToFd(file_contents, fd)) {
        return ErrnoError() << "Unable to write file contents";
    }
    fsync(fd);
    fd.reset();

    if (rename(temp_filename.c_str(), persistent_property_filename.c_str())) {
        int saved_errno = errno;
        unlink(temp_filename.c_str());
        return Error(saved_errno) << "Unable to rename persistent property file";
    }
    return Success();
}

// Persistent properties are not written often, so we rather not keep any data in memory and read
// then rewrite the persistent property file for each update.
void WritePersistentProperty(const std::string& name, const std::string& value) {
    auto persistent_properties = LoadPersistentPropertyFile();
    if (!persistent_properties) {
        LOG(ERROR) << "Recovering persistent properties from memory: "
                   << persistent_properties.error();
        persistent_properties = LoadPersistentPropertiesFromMemory();
    }
    auto it = std::find_if(persistent_properties->begin(), persistent_properties->end(),
                           [&name](const auto& entry) { return entry.first == name; });
    if (it != persistent_properties->end()) {
        *it = {name, value};
    } else {
        persistent_properties->emplace_back(name, value);
    }

    if (auto result = WritePersistentPropertyFile(*persistent_properties); !result) {
        LOG(ERROR) << "Could not store persistent property: " << result.error();
    }
}

std::vector<std::pair<std::string, std::string>> LoadPersistentProperties() {
    auto persistent_properties = LoadPersistentPropertyFile();

    if (!persistent_properties) {
        LOG(ERROR) << "Could not load single persistent property file, trying legacy directory: "
                   << persistent_properties.error();
        persistent_properties = LoadLegacyPersistentProperties();
        if (!persistent_properties) {
            LOG(ERROR) << "Unable to load legacy persistent properties: "
                       << persistent_properties.error();
            return {};
        }
        if (auto result = WritePersistentPropertyFile(*persistent_properties); result) {
            RemoveLegacyPersistentPropertyFiles();
        } else {
            LOG(ERROR) << "Unable to write single persistent property file: " << result.error();
            // Fall through so that we still set the properties that we've read.
        }
    }

    return *persistent_properties;
}

}  // namespace init
}  // namespace android

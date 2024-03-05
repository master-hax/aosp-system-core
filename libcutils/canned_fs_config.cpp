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

#include <private/android_filesystem_config.h>
#include <private/canned_fs_config.h>
#include <private/fs_config.h>

#include <android-base/strings.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using android::base::ConsumePrefix;
using android::base::StartsWith;
using android::base::Tokenize;

struct Entry {
    std::string path;
    unsigned uid;
    unsigned gid;
    unsigned mode;
    uint64_t capabilities;
};

static std::vector<Entry> canned_data;

/*
 * Extracts and removes the file name from the input line.
 *
 * Since a file name can have space in between, this function
 * looks for such file names between a single OR double quote ('/").
 * For example:
 *   "file name (1).txt"
 *   'file name (2).txt'
 * Using SPACE ( ) as a delimiter for tokenizing fails to identify
 * such file names.
 * So, this function is implemented specifically to retrieve the
 * file names.
 *
 * Upon success, the extracted file name is returned.
 * Returns empty file name upon error.
 */
static std::string extractAndRemoveFileName(std::string& line) {
    // Look for file names within '' or "".
    bool fileNameWithSpaces = false;
    size_t base = line.find_first_of("'\"", 0);
    size_t end = 0;

    if (base != line.npos) {
        end = line.find_first_of("'\"", base + 1);
        if (end == line.npos) {
            // Error: return empty filename!
            return "";
        }
        // include the " or ' too.
        end = end + 1;
        fileNameWithSpaces = true;
    } else {
        base = line.find_first_not_of(" ", end);
        if (base == line.npos) {
            // Error: return empty filename!
            return "";
        }
        end = line.find_first_of(" ", base);
        if (end == line.npos) {
            end = line.size();
        }
    }

    // Extract the file-name and remove the same from the input.
    std::string fileName = line.substr(base, end - base);
    size_t len = end - base;
    if (!fileNameWithSpaces) {
        len += 1;
    }
    line.erase(base, len);

    return fileName;
}

int load_canned_fs_config(const char* fn) {
    std::ifstream input(fn);
    for (std::string line; std::getline(input, line);) {
        // Historical: the root dir can be represented as a space character.
        // e.g. " 1000 1000 0755" is parsed as
        // path = " ", uid = 1000, gid = 1000, mode = 0755.
        // But at the same time, we also have accepted
        // "/ 1000 1000 0755".
        if (StartsWith(line, " ")) {
            line.insert(line.begin(), '/');
        }

        // extract and remove the file name (path) from the line.
        std::string fileName = extractAndRemoveFileName(line);
        if (fileName.empty()) {
            std::cerr << "Ill-formed line: " << line << " in " << fn << std::endl;
            return -1;
        }
        // Historical: remove the leading '/' if exists.
        std::string path(fileName.front() == '/' ? std::string(fileName, 1) : fileName);

        // Tokenize the rest of the line.
        std::vector<std::string> tokens = Tokenize(line, " ");
        if (tokens.size() < 3) {
            std::cerr << "Ill-formed line: " << line << " in " << fn << std::endl;
            return -1;
        }

        Entry e{
                .path = std::move(path),
                .uid = static_cast<unsigned int>(atoi(tokens[0].c_str())),
                .gid = static_cast<unsigned int>(atoi(tokens[1].c_str())),
                // mode is in octal
                .mode = static_cast<unsigned int>(strtol(tokens[2].c_str(), nullptr, 8)),
                .capabilities = 0,
        };

        for (size_t i = 3; i < tokens.size(); i++) {
            std::string_view sv = tokens[i];
            if (ConsumePrefix(&sv, "capabilities=")) {
                e.capabilities = strtoll(std::string(sv).c_str(), nullptr, 0);
                break;
            }
            // Historical: there can be tokens like "selabel=..." here. They have been ignored.
            // It's not an error because selabels are applied separately in e2fsdroid using the
            // file_contexts files set via -S option.
            std::cerr << "info: ignored token \"" << sv << "\" in " << fn << std::endl;
        }

        canned_data.emplace_back(std::move(e));
    }

    // Note: we used to sort the entries by path names. This was to improve the lookup performance
    // by doing binary search. However, this is no longer the case. The lookup performance is not
    // critical because this tool runs on the host, not on the device. Now, there can be multiple
    // entries for the same path. Then the one that comes the last wins. This is to allow overriding
    // platform provided fs_config with a user provided fs_config by appending the latter to the
    // former.
    //
    // To implement the strategy, reverse the entries order, and search from the top.
    std::reverse(canned_data.begin(), canned_data.end());

    std::cout << "loaded " << canned_data.size() << " fs_config entries" << std::endl;
    return 0;
}

void canned_fs_config(const char* path, [[maybe_unused]] int dir,
                      [[maybe_unused]] const char* target_out_path, unsigned* uid, unsigned* gid,
                      unsigned* mode, uint64_t* capabilities) {
    if (path != nullptr && path[0] == '/') path++;  // canned paths lack the leading '/'

    const Entry* found = nullptr;
    // canned_data is already reversed. First match wins.
    for (const auto& entry : canned_data) {
        if (path == entry.path) {
            found = &entry;
            break;
        }
        continue;
    }

    if (found == nullptr) {
        std::cerr << "failed to find " << path << " in canned fs_config" << std::endl;
        exit(1);
    }

    *uid = found->uid;
    *gid = found->gid;
    *mode = found->mode;
    *capabilities = found->capabilities;
}

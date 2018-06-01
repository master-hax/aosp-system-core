/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <android-base/logging.h>
#include <android-base/strings.h>
#include <fs_mgr.h>
#include <sparse/sparse.h>

#include <optional>

constexpr uint32_t SPARSE_HEADER_MAGIC = 0xed26ff3a;

std::optional<std::string> blockdev_search(std::string name) {
    static const std::string path = "/dev/block/platform/soc";
    struct dirent* subsoc;
    DIR* soc = opendir(path.c_str());
    if (soc == nullptr) {
        PLOG(ERROR) << "failed to open soc";
        return {};
    }
    while ((subsoc = readdir(soc)) != nullptr) {
        if (subsoc->d_type != DT_DIR || strcmp(subsoc->d_name, ".") == 0 ||
            strcmp(subsoc->d_name, "..") == 0) {
            continue;
        }
        struct dirent* part;
        std::string by_name_path = path + "/" + subsoc->d_name + "/by-name";
        DIR* by_name = opendir(by_name_path.c_str());
        if (by_name == nullptr) {
            PLOG(ERROR) << "Failed to open by-name " << by_name_path;
            continue;
        }
        while ((part = readdir(by_name)) != nullptr) {
            if (name == part->d_name) {
                return by_name_path + "/" + name;
            }
        }
    }
    return {};
}

int get_partition_device(std::string name) {
    auto path = blockdev_search(name);
    if (path) {
        return open(path->c_str(), O_WRONLY | O_EXCL);
    }
    return -1;
}

int flash_raw_data_chunk(int fd, const char* data, size_t len) {
    size_t ret = 0;
    while (ret < len) {
        int this_len = std::min(1048576UL * 8, len - ret);
        int this_ret = write(fd, data, this_len);
        if (this_ret < 0) {
            PLOG(ERROR) << "Failed to flash data of len " << len;
            return -1;
        }
        data += this_ret;
        ret += this_ret;
    }
    return 0;
}

int flash_raw_data(int fd, std::vector<char>& downloaded_data) {
    int ret = flash_raw_data_chunk(fd, downloaded_data.data(), downloaded_data.size());
    if (ret < 0) {
        return -errno;
    }
    return ret;
}

int write_callback(void* priv, const void* data, size_t len) {
    int fd = reinterpret_cast<long long>(priv);
    if (data == nullptr) {
        lseek64(fd, len, SEEK_CUR);
    } else {
        return flash_raw_data_chunk(fd, reinterpret_cast<const char*>(data), len);
    }
    return 0;
}

int flash_sparse_data(int fd, std::vector<char>& downloaded_data) {
    struct sparse_file* file = sparse_file_import_buf(downloaded_data.data(), true, false);
    if (file == nullptr) {
        return false;
    }
    return sparse_file_callback(file, false, false, write_callback, reinterpret_cast<void*>(fd));
}

int flash_block_device(int fd, std::vector<char>& downloaded_data) {
    lseek64(fd, 0, SEEK_SET);
    if (downloaded_data.size() >= sizeof(SPARSE_HEADER_MAGIC) &&
        *reinterpret_cast<uint32_t*>(downloaded_data.data()) == SPARSE_HEADER_MAGIC) {
        return flash_sparse_data(fd, downloaded_data);
    } else {
        return flash_raw_data(fd, downloaded_data);
    }
}

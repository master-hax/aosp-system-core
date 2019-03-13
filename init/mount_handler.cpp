/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "mount_handler.h"

#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <fs_mgr.h>
#include <fstab/fstab.h>

#include "epoll.h"
#include "property_service.h"

namespace android {
namespace init {

namespace {

std::tuple<std::string, std::string, std::string> parse_mount(const std::string& line) {
    auto fields = android::base::Split(line, " ");
    while (fields.size() < 3) fields.emplace_back("");
    if (fields[0] == "/dev/root") {
        android::fs_mgr::Fstab fstab;
        if (android::fs_mgr::ReadDefaultFstab(&fstab)) {
            if (auto entry = GetEntryForMountPoint(&fstab, "/")) {
                if (entry->fs_mgr_flags.logical) fs_mgr_update_logical_partition(entry);
                fields[0] = entry->blk_device;
            }
        }
    }
    if (android::base::StartsWith(fields[0], "/dev/")) {
        if (std::string ret(""); android::base::Readlink(fields[0], &ret)) {
            fields[0] = ret;
        }
    }
    return std::make_tuple(fields[0], fields[1], fields[2]);
}

void set_mount_property(const std::tuple<std::string, std::string, std::string>& parse, bool add) {
    auto [blk_device, mount_point, fs_type] = parse;
    static constexpr char devblock[] = "/dev/block/";
    if (!android::base::StartsWith(blk_device, devblock)) return;
    if (struct stat sb = {}; stat(mount_point.c_str(), &sb) || !S_ISDIR(sb.st_mode)) return;
    std::string property = "dev.mnt.cls" + ((mount_point == "/") ? "/root" : mount_point);
    std::transform(property.begin(), property.end(), property.begin(),
                   [](char c) { return (c == '/') ? '.' : c; });
    std::string value;
    if (add) {
        value = blk_device.substr(strlen(devblock));
        if (android::base::StartsWith(value, "sd")) {
            auto it = std::find_if(value.begin(), value.end(), [](char c) { return isdigit(c); });
            if (it != value.end()) value.erase(it, value.end());
        }
    }
    if (!add && android::base::GetProperty(property, "").empty()) return;
    property_set(property, value);
}

}  // namespace

MountHandler::MountHandler(Epoll* epoll)
    : epoll_(epoll), fd_(::open("/proc/mounts", O_RDONLY | O_CLOEXEC)) {
    if (fd_ == -1) PLOG(FATAL) << "Could not watch /proc/mounts";
    auto result =
            epoll->RegisterHandler(fd_, [this]() { this->mount_handler(); }, EPOLLERR | EPOLLPRI);
    if (!result) LOG(FATAL) << result.error();
}

MountHandler::~MountHandler() {
    if (fd_) epoll_->UnregisterHandler(fd_).IgnoreError();
}

void MountHandler::mount_handler() {
    ::lseek(fd_, 0, SEEK_SET);
    std::string content;
    if (ReadFdToString(fd_, &content)) {
        auto it = mounts_.begin();
        for (auto line : android::base::Split(content, "\n")) {
            auto parse = parse_mount(line);
            auto match = std::find(it, mounts_.end(), line);
            if (match == mounts_.end()) {
                if ((it != mounts_.end()) && (parse_mount(*it) == parse)) {
                    *it = line;
                } else {
                    set_mount_property(parse, true);
                    it = mounts_.insert(it, line);
                }
            } else {
                while (it != match) {
                    set_mount_property(parse_mount(*it), false);
                    it = mounts_.erase(it);
                    match = std::find(it, mounts_.end(), line);
                }
            }
            ++it;
        }
        while (it != mounts_.end()) {
            set_mount_property(parse_mount(*it), false);
            it = mounts_.erase(it);
        }
    }
}

}  // namespace init
}  // namespace android

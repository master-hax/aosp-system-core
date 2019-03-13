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
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <fs_mgr.h>
#include <fstab/fstab.h>

#include "epoll.h"
#include "property_service.h"

namespace android {
namespace init {

namespace {

struct ParseMountReturn {
    std::string blk_device;
    std::string mount_point;
    std::string fs_type;

    bool operator==(const ParseMountReturn& r) const {
        return (blk_device == r.blk_device) && (mount_point == r.mount_point) &&
               (fs_type == r.fs_type);
    }
};

ParseMountReturn ParseMount(const std::string& line) {
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
        if (std::string link; android::base::Readlink(fields[0], &link)) {
            fields[0] = link;
        }
    }
    return {fields[0], fields[1], fields[2]};
}

void SetMountProperty(const ParseMountReturn& parse, bool add) {
    static constexpr char devblock[] = "/dev/block/";
    if (!android::base::StartsWith(parse.blk_device, devblock)) return;
    if (struct stat sb = {}; stat(parse.mount_point.c_str(), &sb) || !S_ISDIR(sb.st_mode)) return;
    std::string property =
            "dev.mnt.blk" + ((parse.mount_point == "/") ? "/root" : parse.mount_point);
    std::replace(property.begin(), property.end(), '/', '.');
    std::string value;
    if (add) {
        value = parse.blk_device.substr(strlen(devblock));
        if (android::base::StartsWith(value, "sd")) {
            // All sd partitions inherit their queue characteristics
            // from the whole device reference.  Strip partition number.
            auto it = std::find_if(value.begin(), value.end(), [](char c) { return isdigit(c); });
            if (it != value.end()) value.erase(it, value.end());
        }
    }
    if (!add && android::base::GetProperty(property, "").empty()) return;
    property_set(property, value);
}

}  // namespace

MountHandler::MountHandler(Epoll* epoll) : epoll_(epoll), fp_(fopen("/proc/mounts", "re"), fclose) {
    if (!fp_) PLOG(FATAL) << "Could not open /proc/mounts";
    auto result = epoll->RegisterHandler(
            fileno(fp_.get()), [this]() { this->MountHandlerFunction(); }, EPOLLERR | EPOLLPRI);
    if (!result) LOG(FATAL) << result.error();
}

MountHandler::~MountHandler() {
    if (fp_) epoll_->UnregisterHandler(fileno(fp_.get())).IgnoreError();
}

void MountHandler::MountHandlerFunction() {
    rewind(fp_.get());
    char* buf = nullptr;
    size_t len = 0;
    auto it = mounts_.begin();
    while (getline(&buf, &len, fp_.get()) != -1) {
        auto line = std::string(buf, len);
        auto match = std::find(it, mounts_.end(), line);
        if (match == mounts_.end()) {
            auto parse = ParseMount(line);
            if ((it != mounts_.end()) && (ParseMount(*it) == parse)) {
                *it = std::move(line);
            } else {
                SetMountProperty(parse, true);
                it = mounts_.insert(it, std::move(line));
            }
        } else {
            while (it != match) {
                SetMountProperty(ParseMount(*it), false);
                it = mounts_.erase(it);
                match = std::find(it, mounts_.end(), line);
            }
        }
        ++it;
    }
    free(buf);
    while (it != mounts_.end()) {
        SetMountProperty(ParseMount(*it), false);
        it = mounts_.erase(it);
    }
}

}  // namespace init
}  // namespace android

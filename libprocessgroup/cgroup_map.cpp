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

//#define LOG_NDEBUG 0
#define LOG_TAG "libprocessgroup"

#include <errno.h>
#include <fcntl.h>
#include <fstab/fstab.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <regex>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <json/reader.h>
#include <json/value.h>
#include <processgroup/cgroup_map.h>
#include <processgroup/processgroup.h>

using android::base::GetBoolProperty;
using android::base::StringPrintf;
using android::base::unique_fd;

static constexpr const char* CGROUPS_DESC_FILE = "/etc/cgroups.json";
static constexpr const char* CGROUPS_RC_FILE = "/dev/cg/cgroup.rc";

static constexpr const char* CGROUP_PROCS_FILE = "/cgroup.procs";
static constexpr const char* CGROUP_TASKS_FILE = "/tasks";
static constexpr const char* CGROUP_TASKS_FILE_V2 = "/cgroup.tasks";

CgroupController::CgroupController(uint32_t version, const std::string& name,
                                   const std::string& path) {
    version_ = version;
    strncpy(name_, name.c_str(), sizeof(name_) - 1);
    name_[sizeof(name_) - 1] = '\0';
    strncpy(path_, path.c_str(), sizeof(path_) - 1);
    path_[sizeof(path_) - 1] = '\0';
}

std::string CgroupController::GetTasksFilePath(const std::string& path) const {
    std::string tasks_path = path_;

    if (!path.empty()) {
        tasks_path += "/" + path;
    }
    return (version_ == 1) ? tasks_path + CGROUP_TASKS_FILE : tasks_path + CGROUP_TASKS_FILE_V2;
}

bool CgroupController::GetProcessGroup(int tid, std::string* group) const {
    if (group == nullptr) {
        return false;
    }

    std::string file_name = StringPrintf("/proc/%d/cgroup", tid);
    std::string content;
    if (!android::base::ReadFileToString(file_name, &content)) {
        LOG(ERROR) << "Failed to read " << file_name;
        return false;
    }

    std::string cg_tag = StringPrintf(":%s:", name_);
    size_t start_pos = content.find(cg_tag);
    if (start_pos == std::string::npos) {
        return false;
    }

    start_pos += cg_tag.length() + 1;  // skip '/'
    size_t end_pos = content.find('\n', start_pos);
    if (end_pos == std::string::npos) {
        *group = content.substr(start_pos, std::string::npos);
    } else {
        *group = content.substr(start_pos, end_pos - start_pos);
    }

    return true;
}

std::string CgroupController::GetProcsFilePath(const std::string& path, uid_t uid,
                                               pid_t pid) const {
    std::string proc_path(path_);
    proc_path.append("/").append(path);
    proc_path = regex_replace(proc_path, std::regex("<uid>"), std::to_string(uid));
    proc_path = regex_replace(proc_path, std::regex("<pid>"), std::to_string(pid));

    return proc_path.append(CGROUP_PROCS_FILE);
}

CgroupDescriptor::CgroupDescriptor(uint32_t version, const std::string& name,
                                   const std::string& path, mode_t mode, const std::string& uid,
                                   const std::string& gid)
    : controller_(version, name, path), mode_(mode), uid_(uid), gid_(gid) {}

CgroupMap::CgroupMap() : cg_file_data_(nullptr), cg_file_size_(0) {
    if (!LoadRcFile()) {
        PLOG(ERROR) << "CgroupMap::Load called for [" << getpid() << "] failed";
    }
}

CgroupMap::~CgroupMap() {
    if (cg_file_data_) {
        munmap(cg_file_data_, cg_file_size_);
        cg_file_data_ = nullptr;
        cg_file_size_ = 0;
    }
}

CgroupMap& CgroupMap::GetInstance() {
    static CgroupMap instance;
    return instance;
}

bool CgroupMap::LoadRcFile() {
    struct stat sb;

    if (cg_file_data_) {
        // Data already initialized
        return true;
    }

    unique_fd fd(TEMP_FAILURE_RETRY(open(CGROUPS_RC_FILE, O_RDONLY | O_CLOEXEC)));
    if (fd < 0) {
        PLOG(ERROR) << "Error in open";
        return false;
    }

    if (fstat(fd, &sb) < 0) {
        PLOG(ERROR) << "Error in fstat";
        return false;
    }

    cg_file_size_ = sb.st_size;
    if (cg_file_size_ < sizeof(struct CgroupFile)) {
        PLOG(ERROR) << "Invalid file format " << CGROUPS_RC_FILE;
        return false;
    }

    cg_file_data_ = (struct CgroupFile*)mmap(nullptr, cg_file_size_, PROT_READ, MAP_SHARED, fd, 0);
    if (cg_file_data_ == MAP_FAILED) {
        PLOG(ERROR) << "Error in mmap";
        return false;
    }

    return true;
}

void CgroupMap::Print() {
    LOG(INFO) << "File version = " << cg_file_data_->version_;
    LOG(INFO) << "File controller count = " << cg_file_data_->controller_count_;

    LOG(INFO) << "Mounted cgroups:";
    CgroupController* controller = (CgroupController*)(cg_file_data_ + 1);
    for (int i = 0; i < cg_file_data_->controller_count_; i++, controller++) {
        LOG(INFO) << "\t" << controller->name() << " ver " << controller->version() << " path "
                  << controller->path();
    }
}

bool CgroupMap::ReadDescriptors(std::map<std::string, CgroupDescriptor>* descriptors) {
    std::vector<CgroupDescriptor> result;
    std::string json_doc;

    if (!android::base::ReadFileToString(CGROUPS_DESC_FILE, &json_doc)) {
        LOG(ERROR) << "Failed to read task profiles from " << CGROUPS_DESC_FILE;
        return false;
    }

    Json::Reader reader;
    Json::Value root;
    if (!reader.parse(json_doc, root)) {
        LOG(ERROR) << "Failed to parse cgroups description: " << reader.getFormattedErrorMessages();
        return false;
    }

    Json::Value cgroups = root["Cgroups"];
    for (Json::Value::ArrayIndex i = 0; i < cgroups.size(); ++i) {
        std::string name = cgroups[i]["Controller"].asString();
        descriptors->emplace(std::make_pair(
                name,
                CgroupDescriptor(1, name, cgroups[i]["Path"].asString(), cgroups[i]["Mode"].asInt(),
                                 cgroups[i]["UID"].asString(), cgroups[i]["GID"].asString())));
    }

    Json::Value cgroups2 = root["Cgroups2"];
    descriptors->emplace(std::make_pair(
            CGROUPV2_CONTROLLER_NAME,
            CgroupDescriptor(2, CGROUPV2_CONTROLLER_NAME, cgroups2["Path"].asString(),
                             cgroups2["Mode"].asInt(), cgroups2["UID"].asString(),
                             cgroups2["GID"].asString())));

    return true;
}

bool CgroupMap::WriteRcFile(const std::map<std::string, CgroupDescriptor>& descriptors) {
    unique_fd fd(TEMP_FAILURE_RETRY(open(CGROUPS_RC_FILE, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC,
                                         S_IRUSR | S_IRGRP | S_IROTH)));
    if (fd < 0) {
        PLOG(ERROR) << "Error in open()";
        return false;
    }

    struct CgroupFile fl;
    fl.version_ = CgroupFile::FILE_CURR_VERSION;
    fl.controller_count_ = descriptors.size();
    int ret = TEMP_FAILURE_RETRY(write(fd, &fl, sizeof(fl)));
    if (ret < 0) {
        PLOG(ERROR) << "Error in write()";
        return false;
    }

    for (const auto& [name, descriptor] : descriptors) {
        ret = TEMP_FAILURE_RETRY(write(fd, descriptor.controller(), sizeof(CgroupController)));
        if (ret < 0) {
            PLOG(ERROR) << "Error in write()";
            return false;
        }
    }

    return true;
}

const CgroupController* CgroupMap::FindController(const std::string& name) const {
    if (!cg_file_data_) {
        return nullptr;
    }

    CgroupController* controller = (CgroupController*)(cg_file_data_ + 1);
    for (int i = 0; i < cg_file_data_->controller_count_; i++, controller++) {
        if (name == controller->name()) {
            return controller;
        }
    }
    return nullptr;
}

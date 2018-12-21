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

//#define LOG_NDEBUG 0
#define LOG_TAG "libprocessgroup"

#include <fcntl.h>
#include <task_profiles.h>
#include <utils.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>

#include <cutils/android_filesystem_config.h>

#include <json/reader.h>
#include <json/value.h>

using android::base::StringPrintf;
using android::base::WriteStringToFile;

#define CGROUPS_DB_FILE "/dev/cgroup.rc"
#define TASK_PROFILE_DB_FILE "/etc/init/task_profiles.json"

TaskProfiles TaskProfiles::instance_;
std::once_flag TaskProfiles::init_flag_;

static int __sys_supports_timerslack = -1;

int ProfileAttribute::GetPathForTask(int tid, std::string& path) const {
    std::string subgroup;
    if (CgroupMap::GetProcessGroup(controller_, tid, subgroup) != 0) {
        return -1;
    }

    if (subgroup.empty()) {
        path = StringPrintf("%s/%s", CgroupMap::GetControllerPath(controller_), file_name_.c_str());
    } else {
        path = StringPrintf("%s/%s/%s", CgroupMap::GetControllerPath(controller_), subgroup.c_str(),
                            file_name_.c_str());
    }
    return 0;
}

int SetClampsAction::ExecuteForProcess(uid_t, pid_t) const {
    // TODO:
    LOG(WARNING) << "SetClampsAction::ExecuteForProcess is not supported";
    return -1;
}

int SetClampsAction::ExecuteForTask(int) const {
    // TODO:
    LOG(WARNING) << "SetClampsAction::ExecuteForTask is not supported";
    return -1;
}

int SetTimerSlackAction::ExecuteForTask(int tid) const {
    set_timerslack_ns(__sys_supports_timerslack == 1, tid, slack_);
    return 0;
}

int SetAttributeAction::ExecuteForProcess(uid_t, pid_t pid) const {
    return ExecuteForTask(pid);
}

int SetAttributeAction::ExecuteForTask(int tid) const {
    std::string path;
    int res;

    res = attr_->GetPathForTask(tid, path);
    if (res < 0) {
        PLOG(ERROR) << "Failed to find cgroup for tid " << tid;
        return res;
    }

    if (!WriteStringToFile(value, path)) {
        PLOG(ERROR) << "Failed to write '" << value << "' to " << path;
        return -errno;
    }

    return 0;
}

SetCgroupAction::~SetCgroupAction() {
    if (fd > 0) {
        close(fd);
    }
}

SetCgroupAction::SetCgroupAction(const struct CgroupMap::CgroupController* c, const std::string& p)
    : controller_(c), path_(p) {
    // cache file descriptor only if path is app independent
    if (!IsAppDependentPath(path_)) {
        std::string tasks_path = CgroupMap::GetTasksFilePath(c, p.c_str());

        if (access(tasks_path.c_str(), W_OK) == 0) {
            fd = open(tasks_path.c_str(), O_WRONLY | O_CLOEXEC);
            if (fd < 0) {
                PLOG(ERROR) << "Failed to cache fd '" << tasks_path << "'";
                fd = -1;
            }
        } else {
            // file is not accessible
            fd = -1;
        }
    } else {
        // file descriptor is not cached
        fd = -2;
    }
}

int SetCgroupAction::ExecuteForProcess(uid_t uid, pid_t pid) const {
    int res;

    if (fd < 0) {
        if (fd == -1) {
            // no permissions to access the file, ignore
            return 0;
        }

        std::string procs_path = CgroupMap::GetProcsFilePath(controller_, path_.c_str(), uid, pid);
        // this is app-dependent path, don't store the file descriptor
        int tmp_fd;

        tmp_fd = open(procs_path.c_str(), O_WRONLY | O_CLOEXEC);
        if (tmp_fd < 0) {
            PLOG(WARNING) << "Failed to open " << procs_path << ": " << strerror(errno);
            return -errno;
        }
        res = add_tid_to_cgroup(pid, tmp_fd);
        close(tmp_fd);
    } else {
        res = add_tid_to_cgroup(pid, fd);
    }
    if (res < 0) {
        PLOG(ERROR) << "Failed to add task into cgroup :" << strerror(errno);
    }

    return res;
}

int SetCgroupAction::ExecuteForTask(int tid) const {
    std::string tasks_path = CgroupMap::GetTasksFilePath(controller_, path_.c_str());
    int res;

    if (fd < 0) {
        // application-dependent path can't be used with tid
        if (fd == -2) {
            PLOG(ERROR) << "Application profile can't be applied to a thread";
            return -1;
        }

        // no permissions to access the file, ignore
        return 0;
    }

    res = add_tid_to_cgroup(tid, fd);
    if (res < 0) {
        PLOG(ERROR) << "Failed to add task into cgroup :" << strerror(errno);
    }

    return res;
}

TaskProfile::~TaskProfile() {
    for (auto iter = elements_.begin(); iter != elements_.end(); ++iter) {
        delete (*iter);
    }
    elements_.clear();
}

int TaskProfile::ExecuteForProcess(uid_t uid, pid_t pid) const {
    for (auto iter = elements_.begin(); iter != elements_.end(); ++iter) {
        int result = (*iter)->ExecuteForProcess(uid, pid);
        if (result != 0) {
            return result;
        }
    }
    return 0;
}

int TaskProfile::ExecuteForTask(int tid) const {
    if (tid == 0) {
        tid = GetTid();
    }
    for (auto iter = elements_.begin(); iter != elements_.end(); ++iter) {
        int result = (*iter)->ExecuteForTask(tid);
        if (result != 0) {
            return result;
        }
    }
    return 0;
}

TaskProfiles::~TaskProfiles() {
    for (auto iter = profiles_.begin(); iter != profiles_.end(); ++iter) {
        delete iter->second;
    }
    profiles_.clear();
    for (auto iter = attributes_.begin(); iter != attributes_.end(); ++iter) {
        delete iter->second;
    }
    attributes_.clear();
}

int TaskProfiles::Load(const CgroupMap& cg_map) {
    std::string json_doc;

    if (!android::base::ReadFileToString(TASK_PROFILE_DB_FILE, &json_doc)) {
        LOG(ERROR) << "Failed to read task profiles from " << TASK_PROFILE_DB_FILE;
        return -1;
    }

    Json::Reader reader;
    Json::Value root;
    if (!reader.parse(json_doc, root)) {
        LOG(ERROR) << "Failed to parse task profiles: " << reader.getFormattedErrorMessages();
        return -1;
    }

    Json::Value attr = root["Attributes"];
    for (Json::Value::ArrayIndex i = 0; i < attr.size(); ++i) {
        std::string name = attr[i]["Name"].asString();
        std::string ctrlName = attr[i]["Controller"].asString();
        std::string file_name = attr[i]["File"].asString();

        if (attributes_.find(name) == attributes_.end()) {
            const struct CgroupMap::CgroupController* controller =
                    cg_map.FindController(ctrlName.c_str());
            if (controller) {
                attributes_[name] = new ProfileAttribute(controller, file_name);
            } else {
                LOG(WARNING) << "Controller " << ctrlName << " is not found";
            }
        } else {
            LOG(WARNING) << "Attribute " << name << " is already defined";
        }
    }

    TaskProfile* profile;
    std::map<std::string, std::string> params;

    Json::Value profilesVal = root["Profiles"];
    for (Json::Value::ArrayIndex i = 0; i < profilesVal.size(); ++i) {
        Json::Value profileVal = profilesVal[i];

        std::string profileName = profileVal["Name"].asString();
        Json::Value actions = profileVal["Actions"];

        profile = new TaskProfile();
        for (Json::Value::ArrayIndex actIdx = 0; actIdx < actions.size(); ++actIdx) {
            Json::Value actionVal = actions[actIdx];
            std::string actionName = actionVal["Name"].asString();
            Json::Value paramsVal = actionVal["Params"];
            if (actionName == "JoinCgroup") {
                std::string ctrlName = paramsVal["Controller"].asString();
                std::string path = paramsVal["Path"].asString();

                const struct CgroupMap::CgroupController* controller =
                        cg_map.FindController(ctrlName.c_str());
                if (controller) {
                    profile->Add(new SetCgroupAction(controller, path));
                } else {
                    LOG(WARNING) << "JoinCgroup: controller " << ctrlName << " is not found";
                }
            } else if (actionName == "SetTimerSlack") {
                std::string slackValue = paramsVal["Slack"].asString();
                char* end;
                unsigned long slack;

                slack = strtoul(slackValue.c_str(), &end, 10);
                if (end > slackValue.c_str()) {
                    profile->Add(new SetTimerSlackAction(slack));
                } else {
                    LOG(WARNING) << "SetTimerSlack: invalid parameter: " << slackValue;
                }
            } else if (actionName == "SetAttribute") {
                std::string attrName = paramsVal["Name"].asString();
                std::string attrValue = paramsVal["Value"].asString();

                auto iter = attributes_.find(attrName);
                if (iter != attributes_.end()) {
                    profile->Add(new SetAttributeAction(iter->second, attrValue));
                } else {
                    LOG(WARNING) << "SetAttribute: unknown attribute: " << attrName;
                }
            } else if (actionName == "SetClamps") {
                std::string boostValue = paramsVal["Boost"].asString();
                std::string clampValue = paramsVal["Clamp"].asString();
                char* end;
                unsigned long boost;

                boost = strtoul(boostValue.c_str(), &end, 10);
                if (end > boostValue.c_str()) {
                    unsigned long clamp = strtoul(clampValue.c_str(), &end, 10);
                    if (end > clampValue.c_str()) {
                        profile->Add(new SetClampsAction(boost, clamp));
                    } else {
                        LOG(WARNING) << "SetClamps: invalid parameter " << clampValue;
                    }
                } else {
                    LOG(WARNING) << "SetClamps: invalid parameter: " << boostValue;
                }
            } else {
                LOG(WARNING) << "Unknown profile action: " << actionName;
            }
        }
        profiles_[profileName] = profile;
    }

    return 0;
}

void TaskProfiles::Init() {
    char buf[64];
    snprintf(buf, sizeof(buf), "/proc/%d/timerslack_ns", getpid());
    __sys_supports_timerslack = !access(buf, W_OK);

    int ret = instance_.Load(CgroupMap::GetInstance());
    if (ret < 0) {
        LOG(ERROR) << "TaskProfiles::Load called for [" << getpid() << "] returns " << ret;
    }
}

const TaskProfile* TaskProfiles::GetProfile(const std::string& name) const {
    auto iter = profiles_.find(name);

    if (iter != profiles_.end()) {
        return iter->second;
    }
    return nullptr;
}

const ProfileAttribute* TaskProfiles::GetAttribute(const std::string& name) const {
    auto iter = attributes_.find(name);

    if (iter != attributes_.end()) {
        return iter->second;
    }
    return nullptr;
}

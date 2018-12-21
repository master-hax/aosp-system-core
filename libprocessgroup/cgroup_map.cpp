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

#include <cgroup_map.h>
#include <errno.h>
#include <fcntl.h>
#include <fstab/fstab.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>

#include <cutils/android_filesystem_config.h>

using android::base::GetBoolProperty;
using android::base::StringPrintf;
using android::base::unique_fd;

#define CGROUP_PROCS_FILE "/cgroup.procs"
#define CGROUP_TASKS_FILE "/tasks"
#define CGROUP_TASKS_FILE_V2 "/cgroup.tasks"

#define CGROUPS_DB_FILE "/dev/cgroup.rc"

// /proc/mounts parsing constants
#define FILE_PROC_MOUNTS "/proc/mounts"

#define MOUNTS_CGROUP_TAG "cgroup"
#define MOUNTS_CGROUP2_TAG "cgroup2"

#define MOUNTS_LINE_ENTRY_CGPATH 1
#define MOUNTS_LINE_ENTRY_CGTAG 2
#define MOUNTS_LINE_ENTRY_CGTYPE 8

// cgroup map file constants
#define FILE_VERSION_1 1
#define FILE_CURR_VERSION FILE_VERSION_1

#define CGROUPV2_DEF_NAME "cgroup2"

void CgroupController::Init(uint32_t version, const std::string& name, const std::string& path) {
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
    std::string file_name = StringPrintf("/proc/%d/cgroup", tid);
    std::string cg_tag = StringPrintf(":%s:", name_);

    if (group == nullptr) {
        return false;
    }

    unique_fd fd(TEMP_FAILURE_RETRY(open(file_name.c_str(), O_RDONLY | O_CLOEXEC)));
    if (fd < 0) {
        return false;
    }

    char buf[256];
    ssize_t r = TEMP_FAILURE_RETRY(read(fd, buf, sizeof(buf) - 1));
    if (r == -1) {
        return false;
    }
    buf[r] = '\0';

    char *pos_start, *pos_end;
    pos_start = strstr(buf, cg_tag.c_str());
    if (pos_start == nullptr) {
        return false;
    }

    pos_start += cg_tag.length() + 1;  // skip '/'
    pos_end = strchr(pos_start, '\n');
    if (pos_end != nullptr) {
        *pos_end = '\0';
    }

    *group = pos_start;
    return true;
}

void CgroupController::ReplaceAll(std::string& str, const std::string& from,
                                  const std::string& to) {
    for (size_t pos = 0;; pos += to.length()) {
        pos = str.find(from, pos);
        if (pos == std::string::npos) break;
        str.erase(pos, from.length());
        str.insert(pos, to);
    }
}

std::string CgroupController::ExpandAppDependentPath(const std::string& cg_path,
                                                     const std::string& subgrp, uid_t uid,
                                                     pid_t pid) {
    std::string p = StringPrintf("%s/%s", cg_path.c_str(), subgrp.c_str());
    ReplaceAll(p, "<uid>", std::to_string(uid));
    ReplaceAll(p, "<pid>", std::to_string(pid));
    return p;
}

std::string CgroupController::GetProcsFilePath(const std::string& path, uid_t uid,
                                               pid_t pid) const {
    std::string procs_path = ExpandAppDependentPath(path_, path, uid, pid);
    return procs_path + CGROUP_PROCS_FILE;
}

CgroupMap::CgroupMap() : cg_file_data_(nullptr), cg_file_size_(0) {
    if (!Load()) {
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

bool CgroupMap::Chown(const std::string& path, uid_t uid, gid_t gid) {
    if (chown(path.c_str(), uid, gid) == -1) {
        int saved_errno = errno;
        rmdir(path.c_str());
        errno = saved_errno;
        return false;
    }

    return true;
}

bool CgroupMap::Write(const std::map<std::string, CgroupController>& cd_detected) {
    unique_fd fd(TEMP_FAILURE_RETRY(open(CGROUPS_DB_FILE, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC,
                                         S_IRUSR | S_IRGRP | S_IROTH)));
    if (fd < 0) {
        PLOG(ERROR) << "Error in open()";
        return false;
    }

    struct CgroupFile fl;
    struct timespec curr_tm;
    fl.version_ = FILE_CURR_VERSION;
    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &curr_tm) != 0) {
        PLOG(ERROR) << "Failed to get current time";
        fl.mod_secs_ = 0;
        fl.mod_nsecs_ = 0;
    } else {
        fl.mod_secs_ = curr_tm.tv_sec;
        fl.mod_nsecs_ = curr_tm.tv_nsec;
    }
    fl.cntrl_count_ = cd_detected.size();
    int ret = TEMP_FAILURE_RETRY(write(fd, &fl, sizeof(fl)));
    if (ret < 0) {
        PLOG(ERROR) << "Error in write()";
        return false;
    }

    for (const auto& [name, cgroup] : cd_detected) {
        ret = TEMP_FAILURE_RETRY(write(fd, &cgroup, sizeof(cgroup)));
        if (ret < 0) {
            PLOG(ERROR) << "Error in write()";
            return false;
        }
    }

    Chown(CGROUPS_DB_FILE, AID_SYSTEM, AID_SYSTEM);

    return true;
}

CgroupMap& CgroupMap::GetInstance() {
    static CgroupMap instance;
    return instance;
}

bool CgroupMap::Load() {
    struct stat sb;

    if (cg_file_data_) {
        // Data already initialized
        return true;
    }

    unique_fd fd(TEMP_FAILURE_RETRY(open(CGROUPS_DB_FILE, O_RDONLY | O_CLOEXEC)));
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
        PLOG(ERROR) << "Invalid file format " << CGROUPS_DB_FILE;
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
    LOG(INFO) << "File last update sec = " << cg_file_data_->mod_secs_;
    LOG(INFO) << "File last update nsec = " << cg_file_data_->mod_nsecs_;
    LOG(INFO) << "File cntrl_count = " << cg_file_data_->cntrl_count_;

    CgroupController* controller = (CgroupController*)(cg_file_data_ + 1);

    LOG(INFO) << "Detected cgroups:";
    for (int i = 0; i < cg_file_data_->cntrl_count_; i++, controller++) {
        LOG(INFO) << "\t" << controller->GetName() << " ver " << controller->GetVersion()
                  << " path " << controller->GetPath();
    }
}

bool CgroupMap::IsCgroupFileSystem(const std::string& system) {
    return (system == "cgroup" || system == "cgroup2" || system == "cpuset");
}

bool CgroupMap::Detect() {
    Fstab fstab;
    if (!ReadFstabFromFile(FILE_PROC_MOUNTS, &fstab)) {
        PLOG(ERROR) << "Cgroups detection failed to open " << FILE_PROC_MOUNTS;
        return false;
    }

    std::string cg2_path;
    CgroupController controller;
    std::map<std::string, CgroupController> cd_detected;
    for (const auto& entry : fstab) {
        if (entry.fs_type == MOUNTS_CGROUP_TAG) {
            size_t name_start, name_end;
            std::string name;

            // cgroup name is the second option separated by a comma
            name_start = entry.fs_options.find(',');
            if (name_start == std::string::npos) {
                continue;
            }

            name_start++;
            name_end = entry.fs_options.find(',', name_start);
            if (name_end == std::string::npos) {
                name = entry.fs_options.substr(name_start);
            } else {
                name = entry.fs_options.substr(name_start, name_end - name_start);
            }
            if (name.empty()) {
                continue;
            }

            controller.Init(1, name, entry.mount_point);
            cd_detected[name] = std::move(controller);
        } else if (entry.fs_type == MOUNTS_CGROUP2_TAG) {
            cg2_path = entry.mount_point.c_str();
        }
    }

    if (!cg2_path.empty()) {
        // Add cgroup v2 as a separate controller
        controller.Init(2, CGROUPV2_DEF_NAME, cg2_path);
        cd_detected[CGROUPV2_DEF_NAME] = std::move(controller);

        // Find out available cgroup v2 controllers
        auto fp = std::unique_ptr<FILE, decltype(&fclose)>{
                fopen((cg2_path + "/cgroup.controllers").c_str(), "r"), fclose};
        if (fp == nullptr) {
            PLOG(ERROR) << "Cgroups detection failed to open " << cg2_path << "/cgroup.controllers";
            return false;
        }

        char line[256];
        while (fgets(line, sizeof(line), fp.get()) != nullptr) {
            char* pos;

            if ((pos = strchr(line, '\n')) != nullptr) {
                *pos = '\0';
            }
            controller.Init(2, line, cg2_path);
            cd_detected[line] = std::move(controller);
        }
    }

    return Write(cd_detected);
}

const CgroupController* CgroupMap::FindController(const std::string& name) const {
    if (!cg_file_data_) {
        return nullptr;
    }

    CgroupController* controller = (CgroupController*)(cg_file_data_ + 1);
    for (int i = 0; i < cg_file_data_->cntrl_count_; i++, controller++) {
        if (name == controller->GetName()) {
            return controller;
        }
    }
    return nullptr;
}

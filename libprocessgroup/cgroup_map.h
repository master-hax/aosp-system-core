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

#pragma once

#include <sys/cdefs.h>
#include <sys/types.h>

#include <map>
#include <mutex>
#include <string>

class CgroupController {
  public:
    void Init(uint32_t version, const std::string& name, const std::string& path);

    uint32_t GetVersion() const { return version_; }
    const char* GetName() const { return name_; }
    const char* GetPath() const { return path_; }

    std::string GetTasksFilePath(const std::string& path) const;
    bool GetProcessGroup(int tid, std::string* group) const;
    std::string GetProcsFilePath(const std::string& path, uid_t uid, pid_t pid) const;

  private:
    static constexpr size_t CGROUP_NAME_BUF_SZ = 16;
    static constexpr size_t CGROUP_PATH_BUF_SZ = 32;

    uint32_t version_;
    char name_[CGROUP_NAME_BUF_SZ];
    char path_[CGROUP_PATH_BUF_SZ];

    static void ReplaceAll(std::string& str, const std::string& from, const std::string& to);
    static std::string ExpandAppDependentPath(const std::string& cg_path, const std::string& subgrp,
                                              uid_t uid, pid_t pid);
};

class CgroupMap {
  public:
    // Should be used by all users
    static CgroupMap& GetInstance();

    // Should be used only by init process for cgroup detection
    static bool IsCgroupFileSystem(const std::string& system);
    static bool Detect();

    // Find cgroup controller record
    const CgroupController* FindController(const std::string& name) const;

  private:
    struct CgroupFile {
        uint32_t version_;
        uint32_t cntrl_count_;
        // not storing struct timespec for modification time
        // directly because of variable size (8 or 16 bytes)
        uint32_t mod_secs_;
        uint32_t mod_nsecs_;
        CgroupController cntrl_[];
    };

    // TODO: change to CgroupFile
    struct CgroupFile* cg_file_data_;
    size_t cg_file_size_;

    CgroupMap();
    ~CgroupMap();

    static bool Chown(const std::string& path, uid_t uid, gid_t gid);
    static bool Write(const std::map<std::string, CgroupController>& map);

    bool Load();
    void Print();
};

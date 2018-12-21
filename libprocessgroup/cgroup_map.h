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

#pragma once

#include <sys/cdefs.h>
#include <sys/types.h>

#include <map>
#include <mutex>
#include <string>

class CgroupMap {
  public:
    static constexpr size_t CGROUP_NAME_BUF_SZ = 16;
    static constexpr size_t CGROUP_PATH_BUF_SZ = 32;

    struct CgroupController {
        uint32_t version_;
        char name_[CGROUP_NAME_BUF_SZ];
        char path_[CGROUP_PATH_BUF_SZ];
    };

    CgroupMap(const CgroupMap&) = delete;
    CgroupMap& operator=(const CgroupMap&) = delete;

    // Should be used only by init process for cgroup detection
    static bool IsCgroupSystem(const std::string& system);
    static int Detect();

    // Should be used by all users
    static const CgroupMap& GetInstance() {
        std::call_once(init_flag_, CgroupMap::Init);
        return instance_;
    }

    // Find cgroup controller record
    const struct CgroupController* FindController(const std::string& name) const;

    // Operations using a cgroup controller record
    static std::string GetTasksFilePath(const struct CgroupController* controller,
                                        const std::string& path);
    static int GetProcessGroup(const struct CgroupController* controller, int tid,
                               std::string& group);
    static const char* GetControllerName(const struct CgroupController* controller);
    static const char* GetControllerPath(const struct CgroupController* controller);
    static std::string GetProcsFilePath(const struct CgroupController* controller,
                                        const std::string& path, uid_t uid, pid_t pid);

  private:
    struct CgroupFile {
        uint32_t version_;
        uint32_t cntrl_count_;
        // not storing struct timespec for modification time
        // directly because of variable size (8 or 16 bytes)
        uint32_t mod_secs_;
        uint32_t mod_nsecs_;
        struct CgroupController cntrl_[];
    };

    // TODO: change to CgroupFile
    char* cg_file_data_;
    size_t cg_file_size_;
    static CgroupMap instance_;
    static std::once_flag init_flag_;

    CgroupMap() : cg_file_data_(nullptr), cg_file_size_(0) {}
    ~CgroupMap();

    static int Write(const std::map<std::string, struct CgroupController>& map);
    static void Init();

    int Load();
    void Print();
};

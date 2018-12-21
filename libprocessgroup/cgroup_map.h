/*
 *  Copyright 2018 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef _CGROUP_MAP_H_
#define _CGROUP_MAP_H_

#include <sys/cdefs.h>
#include <sys/types.h>

#include <map>
#include <string>
#include <mutex>

struct cgroup_controller;

class CgroupMap {
private:
    char *cg_file_data;
    size_t cg_file_size;
    static CgroupMap instance;
    static std::once_flag initFlag;

    CgroupMap() : cg_file_data(NULL), cg_file_size(0) {}
    ~CgroupMap();

    static int Write(const std::map<std::string, struct cgroup_controller>& map);
    static void Init();

    int Load();
    void Print();
public:
    CgroupMap(const CgroupMap&) = delete;
    CgroupMap& operator = (const CgroupMap&) = delete;

    /* Should be used only by init process for cgroup detection */
    static bool IsCgroupSystem(const std::string& system);
    static int Detect();

    /* Should be used by all users */
    static const CgroupMap& GetInstance() {
        std::call_once(initFlag, CgroupMap::Init);
        return instance;
    }

    /* Find cgroup controller record */
    const struct cgroup_controller *FindController(const std::string& name) const;

    /* Operations using a cgroup controller record */
    static std::string GetTasksFilePath(const struct cgroup_controller *controller,
        const std::string& path);
    static int GetProcessGroup(const struct cgroup_controller *controller,
        int tid, std::string& group);
    static const char *GetControllerName(const struct cgroup_controller *controller);
    static const char *GetControllerPath(const struct cgroup_controller *controller);
    static std::string GetProcsFilePath(const struct cgroup_controller *controller,
        const std::string& path, uid_t uid, pid_t pid);

};

#endif

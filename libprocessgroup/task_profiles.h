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

#ifndef _TASK_PROFILES_H_
#define _TASK_PROFILES_H_

#include <cgroup_map.h>
#include <map>
#include <string>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <vector>

class ProfileAttribute {
private:
    const struct cgroup_controller *controller;
    std::string file_name;
public:
    ProfileAttribute(const struct cgroup_controller *c, const std::string fn) :
        controller(c), file_name(fn) {}

    inline const struct cgroup_controller *GetController() const { return controller; }
    inline const std::string& GetFileName() const { return file_name; }

    int GetPathForTask(int tid, std::string& path) const;
};

// Abstract profile element
class ProfileElement {
public:
    virtual ~ProfileElement() {}

    // Default implementations will fail
    virtual int ExecuteForProcess(uid_t, pid_t) const { return -1; };
    virtual int ExecuteForTask(int) const { return -1; };
};

// Profile actions
class SetClampsAction : public ProfileElement {
protected:
    int boost;
    int clamp;
public:
    SetClampsAction(int b, int c) noexcept :
        boost(b), clamp(c) { }

    virtual int ExecuteForProcess(uid_t uid, pid_t pid) const;
    virtual int ExecuteForTask(int tid) const;
};

class SetTimerSlackAction : public ProfileElement {
private:
    unsigned long slack;
public:
    SetTimerSlackAction(unsigned long s) noexcept :
        slack(s) { }

    virtual int ExecuteForTask(int tid) const;
};

// Set attribute profile element
class SetAttributeAction : public ProfileElement {
private:
    const ProfileAttribute *attr;
    std::string value;
public:
    SetAttributeAction(const ProfileAttribute *a, const std::string& v) :
        attr(a), value(v) {}

    virtual int ExecuteForProcess(uid_t uid, pid_t pid) const;
    virtual int ExecuteForTask(int tid) const;
};

// Set cgroup profile element
class SetCgroupAction : public ProfileElement {
private:
    const struct cgroup_controller *controller;
    std::string path;
    int fd;
public:
    SetCgroupAction(const struct cgroup_controller *c, const std::string& p);
    virtual ~SetCgroupAction();

    virtual int ExecuteForProcess(uid_t uid, pid_t pid) const;
    virtual int ExecuteForTask(int tid) const;

    const struct cgroup_controller *GetController() const { return controller; }
    std::string GetPath() const { return path; }
};

class TaskProfile {
private:
    std::vector<ProfileElement*> elements;
public:
    TaskProfile() {}
    ~TaskProfile();

    void Add(ProfileElement* e) { elements.push_back(e); }

    int ExecuteForProcess(uid_t uid, pid_t pid) const;
    int ExecuteForTask(int tid) const;
};

class TaskProfiles {
private:
    std::map<std::string, TaskProfile*> profiles;
    std::map<std::string, ProfileAttribute*> attributes;

    static TaskProfiles instance;
    static std::once_flag initFlag;

    TaskProfiles() = default;
    ~TaskProfiles();

    int Load(const CgroupMap& cg_map);
    static void Init();
public:
    TaskProfiles(const TaskProfiles&) = delete;
    TaskProfiles& operator = (const TaskProfiles&) = delete;

    static const TaskProfiles& GetInstance() {
        std::call_once(initFlag, TaskProfiles::Init);
        return instance;
    }

    const TaskProfile* GetProfile(const std::string& name) const;
    const ProfileAttribute* GetAttribute(const std::string& name) const;
};

#endif

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

#include <cgroup_map.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <map>
#include <string>
#include <vector>

#include <android-base/unique_fd.h>

class ProfileAttribute {
  public:
    ProfileAttribute(const CgroupController* c, const std::string fn)
        : controller_(c), file_name_(fn) {}

    const CgroupController* GetController() const { return controller_; }
    const std::string& GetFileName() const { return file_name_; }

    bool GetPathForTask(int tid, std::string* path) const;

  private:
    const CgroupController* controller_;
    std::string file_name_;
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
  public:
    SetClampsAction(int b, int c) noexcept : boost_(b), clamp_(c) {}

    virtual int ExecuteForProcess(uid_t uid, pid_t pid) const;
    virtual int ExecuteForTask(int tid) const;

  protected:
    int boost_;
    int clamp_;
};

class SetTimerSlackAction : public ProfileElement {
  public:
    SetTimerSlackAction(unsigned long s) noexcept : slack_(s) {}

    virtual int ExecuteForTask(int tid) const;

  private:
    unsigned long slack_;

    static bool IsTimerSlackSupported(int tid);
};

// Set attribute profile element
class SetAttributeAction : public ProfileElement {
  public:
    SetAttributeAction(const ProfileAttribute* a, const std::string& v) : attr_(a), value(v) {}

    virtual int ExecuteForProcess(uid_t uid, pid_t pid) const;
    virtual int ExecuteForTask(int tid) const;

  private:
    const ProfileAttribute* attr_;
    std::string value;
};

// Set cgroup profile element
class SetCgroupAction : public ProfileElement {
  public:
    SetCgroupAction(const CgroupController* c, const std::string& p);

    virtual int ExecuteForProcess(uid_t uid, pid_t pid) const;
    virtual int ExecuteForTask(int tid) const;

    const CgroupController* GetController() const { return controller_; }
    std::string GetPath() const { return path_; }

  private:
    const CgroupController* controller_;
    std::string path_;
    android::base::unique_fd fd_;

    static bool IsAppDependentPath(const std::string& path);
    static bool AddTidToCgroup(int tid, int fd);
};

class TaskProfile {
  public:
    TaskProfile() {}

    void Add(std::unique_ptr<ProfileElement> e) { elements_.push_back(std::move(e)); }

    int ExecuteForProcess(uid_t uid, pid_t pid) const;
    int ExecuteForTask(int tid) const;

  private:
    std::vector<std::unique_ptr<ProfileElement>> elements_;
};

class TaskProfiles {
  public:
    // Should be used by all users
    static TaskProfiles& GetInstance();

    const TaskProfile* GetProfile(const std::string& name) const;
    const ProfileAttribute* GetAttribute(const std::string& name) const;

  private:
    std::map<std::string, std::unique_ptr<TaskProfile>> profiles_;
    std::map<std::string, std::unique_ptr<ProfileAttribute>> attributes_;

    TaskProfiles();

    bool Load(const CgroupMap& cg_map);
};

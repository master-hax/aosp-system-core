/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef _INIT_SERVICE_H
#define _INIT_SERVICE_H

#include <sys/types.h>

#include <memory>
#include <set>
#include <string>
#include <vector>

#include <android-base/chrono_utils.h>
#include <cutils/iosched_policy.h>

#include "action.h"
#include "capabilities.h"
#include "descriptors.h"
#include "init_parser.h"
#include "keyword_map.h"
#include "util.h"

#define NR_SVC_SUPP_GIDS 12    // twelve supplementary groups

class Action;
class ServiceManager;

struct ServiceEnvironmentInfo {
    ServiceEnvironmentInfo();
    ServiceEnvironmentInfo(const std::string& name, const std::string& value);
    std::string name;
    std::string value;
};

class Service {
  public:
    enum class RunningState {
        kStopped = 0,
        kRunning,
        kRestarting,
        kPendingRestart,
    };

    enum class DisabledState {
        kEnabled = 0,
        kDisabled,
        kDisabledClassStarted,  // This service is disabled, but its class has started; it will be
                                // started once enabled
    };

    enum class OneShotExecState {  // Exec implies OneShot, TemporaryExec implies Exec, etc.
        kNormal = 0,
        kOneShot = 1,
        kExec = 2,
        kTemporaryExec = 3,
    };

    Service(const std::string& name, const std::vector<std::string>& args);

    Service(const std::string& name, OneShotExecState one_shot_exec_state, uid_t uid, gid_t gid,
            const std::vector<gid_t>& supp_gids, const CapSet& capabilities,
            unsigned namespace_flags, const std::string& seclabel,
            const std::vector<std::string>& args);

    bool IsRunning() { return running_state_ == RunningState::kRunning; }
    bool ParseLine(const std::vector<std::string>& args, std::string* err);
    bool ExecStart(std::unique_ptr<Timer>* exec_waiter);
    bool Start();
    bool StartIfNotDisabled();
    bool Enable();
    void Reset();
    void Stop();
    void Terminate();
    void Restart();
    void RestartIfNeeded(time_t* process_needs_restart_at);
    void Reap();
    void DumpState() const;
    void SetShutdownCritical() { shutdown_critical_ = true; }
    bool IsShutdownCritical() const { return shutdown_critical_; }

    const std::string& name() const { return name_; }
    const std::set<std::string>& classnames() const { return classnames_; }
    OneShotExecState one_shot_exec_state() const { return one_shot_exec_state_; }
    bool has_console() const { return has_console_; }
    pid_t pid() const { return pid_; }
    uid_t uid() const { return uid_; }
    gid_t gid() const { return gid_; }
    int priority() const { return priority_; }
    const std::vector<gid_t>& supp_gids() const { return supp_gids_; }
    const std::string& seclabel() const { return seclabel_; }
    const std::vector<int>& keycodes() const { return keycodes_; }
    int keychord_id() const { return keychord_id_; }
    void set_keychord_id(int keychord_id) { keychord_id_ = keychord_id; }
    const std::vector<std::string>& args() const { return args_; }

  private:
    using OptionParser = bool (Service::*) (const std::vector<std::string>& args,
                                            std::string* err);
    class OptionParserMap;

    void NotifyStateChange(const std::string& new_state) const;
    void StopService(int signal);
    void ZapStdio() const;
    void OpenConsole() const;
    void KillProcessGroup(int signal);
    void SetProcessAttributes();

    bool ParseCapabilities(const std::vector<std::string>& args, std::string *err);
    bool ParseClass(const std::vector<std::string>& args, std::string* err);
    bool ParseConsole(const std::vector<std::string>& args, std::string* err);
    bool ParseCritical(const std::vector<std::string>& args, std::string* err);
    bool ParseDisabled(const std::vector<std::string>& args, std::string* err);
    bool ParseGroup(const std::vector<std::string>& args, std::string* err);
    bool ParsePriority(const std::vector<std::string>& args, std::string* err);
    bool ParseIoprio(const std::vector<std::string>& args, std::string* err);
    bool ParseKeycodes(const std::vector<std::string>& args, std::string* err);
    bool ParseOneshot(const std::vector<std::string>& args, std::string* err);
    bool ParseOnrestart(const std::vector<std::string>& args, std::string* err);
    bool ParseOomScoreAdjust(const std::vector<std::string>& args, std::string* err);
    bool ParseNamespace(const std::vector<std::string>& args, std::string* err);
    bool ParseSeclabel(const std::vector<std::string>& args, std::string* err);
    bool ParseSetenv(const std::vector<std::string>& args, std::string* err);
    bool ParseSocket(const std::vector<std::string>& args, std::string* err);
    bool ParseFile(const std::vector<std::string>& args, std::string* err);
    bool ParseUser(const std::vector<std::string>& args, std::string* err);
    bool ParseWritepid(const std::vector<std::string>& args, std::string* err);

    template <typename T>
    bool AddDescriptor(const std::vector<std::string>& args, std::string* err);

    std::string name_;
    std::set<std::string> classnames_;
    std::string console_;

    RunningState running_state_;
    DisabledState disabled_state_;
    OneShotExecState one_shot_exec_state_;

    bool rc_disabled_;
    bool has_console_;
    bool critical_;
    bool shutdown_critical_;

    pid_t pid_;
    android::base::boot_clock::time_point time_started_;  // time of last start
    android::base::boot_clock::time_point time_crashed_;  // first crash within inspection window
    int crash_count_;                     // number of times crashed within window

    uid_t uid_;
    gid_t gid_;
    std::vector<gid_t> supp_gids_;
    CapSet capabilities_;
    unsigned namespace_flags_;

    std::string seclabel_;

    std::vector<std::unique_ptr<DescriptorInfo>> descriptors_;
    std::vector<ServiceEnvironmentInfo> envvars_;

    Action onrestart_;  // Commands to execute on restart.

    std::vector<std::string> writepid_files_;

    // keycodes for triggering this service via /dev/keychord
    std::vector<int> keycodes_;
    int keychord_id_;

    IoSchedClass ioprio_class_;
    int ioprio_pri_;
    int priority_;

    int oom_score_adjust_;

    std::vector<std::string> args_;
};

class ServiceManager {
public:
    static ServiceManager& GetInstance();

    void AddService(std::unique_ptr<Service> service);
    Service* MakeExecOneshotService(const std::vector<std::string>& args);
    bool Exec(const std::vector<std::string>& args);
    bool ExecStart(const std::string& name);
    bool IsWaitingForExec() const;
    Service* FindServiceByName(const std::string& name) const;
    Service* FindServiceByPid(pid_t pid) const;
    Service* FindServiceByKeychord(int keychord_id) const;
    void ForEachService(const std::function<void(Service*)>& callback) const;
    void ForEachServiceInClass(const std::string& classname, void (*func)(Service* svc)) const;
    void ReapAnyOutstandingChildren();
    void RemoveService(const Service& svc);
    void DumpState() const;

private:
    ServiceManager();

    // Cleans up a child process that exited.
    // Returns true iff a children was cleaned up.
    bool ReapOneProcess();

    static int exec_count_; // Every service needs a unique name.
    std::unique_ptr<Timer> exec_waiter_;

    std::vector<std::unique_ptr<Service>> services_;
};

class ServiceParser : public SectionParser {
  public:
    ServiceParser(ServiceManager* service_manager)
        : service_manager_(service_manager), service_(nullptr) {}
    bool ParseSection(std::vector<std::string>&& args, const std::string& filename, int line,
                      std::string* err) override;
    bool ParseLineSection(std::vector<std::string>&& args, int line, std::string* err) override;
    void EndSection() override;

  private:
    bool IsValidName(const std::string& name) const;

    ServiceManager* service_manager_;
    std::unique_ptr<Service> service_;
};

#endif

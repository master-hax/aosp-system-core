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

#include <cutils/iosched_policy.h>

#include <string>
#include <vector>

#define SVC_DISABLED       0x001  // do not autostart with class
#define SVC_ONESHOT        0x002  // do not restart on exit
#define SVC_RUNNING        0x004  // currently active
#define SVC_RESTARTING     0x008  // waiting to restart
#define SVC_CONSOLE        0x010  // requires console
#define SVC_CRITICAL       0x020  // will reboot into recovery if keeps crashing
#define SVC_RESET          0x040  // Use when stopping a process, but not disabling so it can be restarted with its class.
#define SVC_RC_DISABLED    0x080  // Remember if the disabled flag was set in the rc script.
#define SVC_RESTART        0x100  // Use to safely restart (stop, wait, start) a service.
#define SVC_DISABLED_START 0x200  // A start was requested but it was disabled at the time.
#define SVC_EXEC           0x400  // This synthetic service corresponds to an 'exec'.

#define NR_SVC_SUPP_GIDS 12    /* twelve supplementary groups */

class Action;
class ServiceManager;

struct SocketInfo {
    SocketInfo(const std::string& name, const std::string& type, uid_t uid,
                       gid_t gid, int perm, const std::string& socketcon);
    const std::string name;
    const std::string type;
    const uid_t uid;
    const gid_t gid;
    const int perm;
    const std::string socketcon;
};

struct ServiceEnvironmentInfo {
    ServiceEnvironmentInfo(const std::string& name, const std::string& value);
    const std::string name;
    const std::string value;
};

class Service {
public:
    friend ServiceManager;
    Service(const std::string& name, const std::string& classname,
            const std::vector<std::string>& args);

    bool HandleLine(int kw, const std::vector<std::string>& args, std::string* err);
    void Start(const std::vector<std::string>& dynamic_args);
    void Start();
    void StartIfNotDisabled();
    void Enable();
    void Reset();
    void Stop();
    void Restart();
    void RestartIfNeeded(time_t process_needs_restart);
    void Wait();

    std::string get_name() const { return name_; }
    void set_keychord_id(int keychord_id) { keychord_id_ = keychord_id; }
    int* get_keycodes() const { return keycodes_; }
    int get_nkeycodes() const { return nkeycodes_; }

private:
    void NotifyStateChange(const std::string& new_state) const;
    void StopOrReset(int how);
    void DumpState() const;
    void ZapStdio() const;
    void OpenConsole() const;
    void PublishSocket(const std::string& name, int fd) const;

    const std::string name_;
    std::string classname_;

    unsigned flags_;
    pid_t pid_;
    time_t time_started_;    /* time of last start */
    time_t time_crashed_;    /* first crash within inspection window */
    int nr_crashed_;         /* number of times crashed within window */

    uid_t uid_;
    gid_t gid_;
    gid_t supp_gids_[NR_SVC_SUPP_GIDS];
    size_t nr_supp_gids_;

    std::string seclabel_;

    std::vector<SocketInfo*> sockets_;
    std::vector<ServiceEnvironmentInfo*> envvars_;

    Action* onrestart_;  /* Commands to execute on restart. */

    std::vector<std::string>* writepid_files_;

    /* keycodes for triggering this service via /dev/keychord */
    int* keycodes_;
    int nkeycodes_;
    int keychord_id_;

    IoSchedClass ioprio_class_;
    int ioprio_pri_;

    const std::vector<std::string> args_;
};

class ServiceManager {
public:
    static ServiceManager& GetInstance();

    Service* AddNewService(const std::string& name, const std::string& classname,
                           const std::vector<std::string>& args,
                           std::string* err);
    Service* MakeExecOneshotService(const std::vector<std::string>& args);
    Service* ServiceFindByName(const std::string& name) const;
    Service* ServiceFindByPid(pid_t pid) const;
    Service* ServiceFindByKeychord(int keychord_id) const;
    void ServiceForEach(void (*func)(Service* svc)) const;
    void ServiceForEachClass(const std::string& classname,
                             void (*func)(Service* svc)) const;
    void ServiceForEachFlags(unsigned matchflags,
                             void (*func)(Service* svc)) const;
    void RemoveService(const Service& svc);
    void DumpState() const;
private:
    ServiceManager();

    bool ValidName(const std::string& name) const;

    static int exec_count; // Every service needs a unique name.
    std::vector<Service*> service_list_;
};

#endif

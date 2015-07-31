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

#include "service.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <selinux/selinux.h>

#include <base/file.h>
#include <base/stringprintf.h>
#include <cutils/android_reboot.h>
#include <cutils/sockets.h>

#include "action.h"
#include "keywords.h"
#include "log.h"
#include "property_service.h"
#include "init.h"
#include "init_parser.h"
#include "util.h"

#define CRITICAL_CRASH_THRESHOLD    4       /* if we crash >4 times ... */
#define CRITICAL_CRASH_WINDOW       (4*60)  /* ... in 4 minutes, goto recovery */

Service::Service(const std::string& name, const std::string& classname,
                 const std::vector<std::string>& args)
    : name_(name), classname_(classname), args_(args)
{
    onrestart_ = new Action();
    onrestart_->InitSingleTrigger("onrestart");
}

void Service::NotifyStateChange(const std::string& new_state) {
    if (!properties_initialized()) {
        // If properties aren't available yet, we can't set them.
        return;
    }

    if ((flags_ & SVC_EXEC) != 0) {
        // 'exec' commands don't have properties tracking their state.
        return;
    }

    char prop_name[PROP_NAME_MAX];
    if (snprintf(prop_name, sizeof(prop_name), "init.svc.%s", name_.c_str()) >= PROP_NAME_MAX) {
        // If the property name would be too long, we can't set it.
        ERROR("Property name \"init.svc.%s\" too long; not setting to %s\n",
              name_.c_str(), new_state.c_str());
        return;
    }

    property_set(prop_name, new_state.c_str());
}

void Service::Wait()
{
    if (!(flags_ & SVC_ONESHOT) || (flags_ & SVC_RESTART)) {
        NOTICE("Service '%s' (pid %d) killing any children in process group\n",
               name_.c_str(), pid_);
        kill(-pid_, SIGKILL);
    }

    // Remove any sockets we may have created.
    for (socketinfo* si = sockets_; si; si = si->next) {
        char tmp[128];
        snprintf(tmp, sizeof(tmp), ANDROID_SOCKET_DIR "/%s", si->name);
        unlink(tmp);
    }

    if (flags_ & SVC_EXEC) {
        INFO("SVC_EXEC pid %d finished...\n", pid_);
        waiting_for_exec = false;
        ServiceManager::GetInstance().RemoveService(*this);
        delete this;
        return;
    }

    pid_ = 0;
    flags_ &= (~SVC_RUNNING);

    // Oneshot processes go into the disabled state on exit,
    // except when manually restarted.
    if ((flags_ & SVC_ONESHOT) && !(flags_ & SVC_RESTART)) {
        flags_ |= SVC_DISABLED;
    }

    // Disabled and reset processes do not get restarted automatically.
    if (flags_ & (SVC_DISABLED | SVC_RESET))  {
        NotifyStateChange("stopped");
        return;
    }

    time_t now = gettime();
    if ((flags_ & SVC_CRITICAL) && !(flags_ & SVC_RESTART)) {
        if (time_crashed_ + CRITICAL_CRASH_WINDOW >= now) {
            if (++nr_crashed_ > CRITICAL_CRASH_THRESHOLD) {
                ERROR("critical process '%s' exited %d times in %d minutes; "
                      "rebooting into recovery mode\n", name_.c_str(),
                      CRITICAL_CRASH_THRESHOLD, CRITICAL_CRASH_WINDOW / 60);
                android_reboot(ANDROID_RB_RESTART2, 0, "recovery");
                return;
            }
        } else {
            time_crashed_ = now;
            nr_crashed_ = 1;
        }
    }

    flags_ &= (~SVC_RESTART);
    flags_ |= SVC_RESTARTING;

    // Execute all onrestart commands for this service.
    onrestart_->ExecuteAllCommands();

    NotifyStateChange("restarting");
    return;
}

bool Service::HandleLine(int kw, const std::vector<std::string>& args, std::string* err)
{
    std::vector<std::string> str_args;

    ioprio_class_ = IoSchedClass_NONE;

    switch (kw) {
    case K_class:
        if (args.size() != 2) {
            *err = "class option requires a classname\n";
            return false;
        } else {
            classname_ = args[1];
        }
        break;
    case K_console:
        flags_ |= SVC_CONSOLE;
        break;
    case K_disabled:
        flags_ |= SVC_DISABLED;
        flags_ |= SVC_RC_DISABLED;
        break;
    case K_ioprio:
        if (args.size() != 3) {
            *err = "ioprio optin usage: ioprio <rt|be|idle> <ioprio 0-7>\n";
            return false;
        } else {
            ioprio_pri_ = std::stoul(args[2], 0, 8);

            if (ioprio_pri_ < 0 || ioprio_pri_ > 7) {
                *err = "priority value must be range 0 - 7\n";
                return false;
            }

            if (!args[1].compare("rt")) {
                ioprio_class_ = IoSchedClass_RT;
            } else if (!args[1].compare("be")) {
                ioprio_class_ = IoSchedClass_BE;
            } else if (!args[1].compare("idle")) {
                ioprio_class_ = IoSchedClass_IDLE;
            } else {
                *err = "ioprio option usage: ioprio <rt|be|idle> <0-7>\n";
                return false;
            }
        }
        break;
    case K_group:
        if (args.size() < 2) {
            *err = "group option requires a group id\n";
            return false;
        } else if (args.size() > NR_SVC_SUPP_GIDS + 2) {
            *err = android::base::StringPrintf("group option accepts at most %d supp. groups\n",
                                               NR_SVC_SUPP_GIDS);
            return false;
        } else {
            std::size_t n;
            gid_ = decode_uid(args[1].c_str());
            for (n = 2; n < args.size(); n++) {
                supp_gids_[n-2] = decode_uid(args[n].c_str());
            }
            nr_supp_gids_ = n - 2;
        }
        break;
    case K_keycodes: //TODO(tomcherry): C++'ify keycodes
        if (args.size() < 2) {
            *err = "keycodes option requires atleast one keycode\n";
            return false;
        } else {
            keycodes_ = (int*) malloc((args.size() - 1) * sizeof(keycodes_[0]));
            if (!keycodes_) {
                *err = "could not allocate keycodes\n";
                return false;
            } else {
                nkeycodes_ = args.size() - 1;
                for (std::size_t i = 1; i < args.size(); i++) {
                    keycodes_[i - 1] = std::stoi(args[i]);
                }
            }
        }
        break;
    case K_oneshot:
        flags_ |= SVC_ONESHOT;
        break;
    case K_onrestart:
        str_args.assign(args.begin() + 1, args.end());
        add_command_to_action(onrestart_, str_args, "", 0, err);
        break;
    case K_critical:
        flags_ |= SVC_CRITICAL;
        break;
    case K_setenv: { /* name value */
        if (args.size() < 3) {
            *err = "setenv option requires name and value arguments\n";
            return false;
        }
        svcenvinfo* ei = (svcenvinfo*) calloc(1, sizeof(*ei));
        if (!ei) {
            *err = "out of memory\n";
            return false;
        }
        ei->name = args[1].c_str();
        ei->value = args[2].c_str();
        ei->next = envvars_;
        envvars_ = ei;
        break;
    }
    case K_socket: {/* name type perm [ uid gid context ] */
        if (args.size() < 4) {
            *err = "socket option requires name, type, perm arguments\n";
            return false;
        }
        if (args[2].compare("dgram") && args[2].compare("stream") &&
            args[2].compare("seqpacket")) {
            *err = "socket type must be 'dgram', 'stream' or 'seqpacket'\n";
            return false;
        }
        socketinfo* si = (socketinfo*) calloc(1, sizeof(*si));
        if (!si) {
            *err = "out of memory\n";
            return false;
        }
        si->name = args[1].c_str();
        si->type = args[2].c_str();
        si->perm = std::stoul(args[3], 0, 8);
        if (args.size() > 4)
            si->uid = decode_uid(args[4].c_str());
        if (args.size() > 5)
            si->gid = decode_uid(args[5].c_str());
        if (args.size() > 6)
            si->socketcon = args[6].c_str();
        si->next = sockets_;
        sockets_ = si;
        break;
    }
    case K_user:
        if (args.size() != 2) {
            *err = "user option requires a user id\n";
            return false;
        } else {
            uid_ = decode_uid(args[1].c_str());
        }
        break;
    case K_seclabel:
        if (args.size() != 2) {
            *err = "seclabel option requires a label string\n";
            return false;
        } else {
            seclabel_ = args[1];
        }
        break;
    case K_writepid:
        if (args.size() < 2) {
            *err = "writepid option requires at least one filename\n";
            return false;
        }
        writepid_files_ = new std::vector<std::string>;
        writepid_files_->assign(args.begin() + 1, args.end());
        break;

    default:
        *err = android::base::StringPrintf("invalid option '%s'\n", args[0].c_str());
        return false;
    }
    return true;
}

void Service::Start(const char* dynamic_args)
{
    // Starting a service removes it from the disabled or reset state and
    // immediately takes it out of the restarting state if it was in there.
    flags_ &= (~(SVC_DISABLED|SVC_RESTARTING|SVC_RESET|SVC_RESTART|SVC_DISABLED_START));
    time_started_ = 0;

    // Running processes require no additional work --- if they're in the
    // process of exiting, we've ensured that they will immediately restart
    // on exit, unless they are ONESHOT.
    if (flags_ & SVC_RUNNING) {
        return;
    }

    bool needs_console = (flags_ & SVC_CONSOLE);
    if (needs_console && !have_console) {
        ERROR("service '%s' requires console\n", name_.c_str());
        flags_ |= SVC_DISABLED;
        return;
    }

    struct stat sb;
    if (stat(args_[0].c_str(), &sb) == -1) {
        ERROR("cannot find '%s' (%s), disabling '%s'\n",
              args_[0].c_str(), strerror(errno), name_.c_str());
        flags_ |= SVC_DISABLED;
        return;
    }

    if ((!(flags_ & SVC_ONESHOT)) && dynamic_args) {
        ERROR("service '%s' must be one-shot to use dynamic args, disabling\n",
              args_[0].c_str());
        flags_ |= SVC_DISABLED;
        return;
    }

    char* scon = NULL;
    if (!seclabel_.empty()) {
        scon = strdup(seclabel_.c_str());
        if (!scon) {
            ERROR("Out of memory while starting '%s'\n", name_.c_str());
            return;
        }
    } else {
        char *mycon = NULL, *fcon = NULL;

        INFO("computing context for service '%s'\n", args_[0].c_str());
        int rc = getcon(&mycon);
        if (rc < 0) {
            ERROR("could not get context while starting '%s'\n", name_.c_str());
            return;
        }

        rc = getfilecon(args_[0].c_str(), &fcon);
        if (rc < 0) {
            ERROR("could not get context while starting '%s'\n", name_.c_str());
            free(mycon);
            return;
        }

        rc = security_compute_create(mycon, fcon, string_to_security_class("process"), &scon);
        if (rc == 0 && !strcmp(scon, mycon)) {
            ERROR("Service %s does not have a SELinux domain defined.\n", name_.c_str());
            free(mycon);
            free(fcon);
            free(scon);
            return;
        }
        free(mycon);
        free(fcon);
        if (rc < 0) {
            ERROR("could not get context while starting '%s'\n", name_.c_str());
            return;
        }
    }

    NOTICE("Starting service '%s'...\n", name_.c_str());

    pid_t pid = fork();
    if (pid == 0) {
        socketinfo* si;
        svcenvinfo* ei;
        char tmp[32];
        int fd, sz;

        umask(077);
        if (properties_initialized()) {
            get_property_workspace(&fd, &sz);
            snprintf(tmp, sizeof(tmp), "%d,%d", dup(fd), sz);
            add_environment("ANDROID_PROPERTY_WORKSPACE", tmp);
        }

        for (ei = envvars_; ei; ei = ei->next)
            add_environment(ei->name, ei->value);

        for (si = sockets_; si; si = si->next) {
            int socket_type = (
                    !strcmp(si->type, "stream") ? SOCK_STREAM :
                        (!strcmp(si->type, "dgram") ? SOCK_DGRAM : SOCK_SEQPACKET));
            int s = create_socket(si->name, socket_type,
                                  si->perm, si->uid, si->gid, si->socketcon ?: scon);
            if (s >= 0) {
                publish_socket(si->name, s);
            }
        }

        free(scon);
        scon = NULL;

        if (writepid_files_) {
            std::string pid_str = android::base::StringPrintf("%d", pid);
            for (auto& file : *writepid_files_) {
                if (!android::base::WriteStringToFile(pid_str, file)) {
                    ERROR("couldn't write %s to %s: %s\n",
                          pid_str.c_str(), file.c_str(), strerror(errno));
                }
            }
        }

        if (ioprio_class_ != IoSchedClass_NONE) {
            if (android_set_ioprio(getpid(), ioprio_class_, ioprio_pri_)) {
                ERROR("Failed to set pid %d ioprio = %d,%d: %s\n",
                      getpid(), ioprio_class_, ioprio_pri_, strerror(errno));
            }
        }

        if (needs_console) {
            setsid();
            open_console();
        } else {
            zap_stdio();
        }

        if (false) {
            for (size_t n = 0; !args_[n].empty(); n++) {
                INFO("args[%zu] = '%s'\n", n, args_[n].c_str());
            }
            for (size_t n = 0; ENV[n]; n++) {
                INFO("env[%zu] = '%s'\n", n, ENV[n]);
            }
        }

        setpgid(0, getpid());

        // As requested, set our gid, supplemental gids, and uid.
        if (gid_) {
            if (setgid(gid_) != 0) {
                ERROR("setgid failed: %s\n", strerror(errno));
                _exit(127);
            }
        }
        if (nr_supp_gids_) {
            if (setgroups(nr_supp_gids_, supp_gids_) != 0) {
                ERROR("setgroups failed: %s\n", strerror(errno));
                _exit(127);
            }
        }
        if (uid_) {
            if (setuid(uid_) != 0) {
                ERROR("setuid failed: %s\n", strerror(errno));
                _exit(127);
            }
        }
        if (!seclabel_.empty()) {
            if (setexeccon(seclabel_.c_str()) < 0) {
                ERROR("cannot setexeccon('%s'): %s\n", seclabel_.c_str(), strerror(errno));
                _exit(127);
            }
        }

        std::vector<char*> strs;
        strs.resize(args_.size());
        for (auto& s : args_) {
            strs.push_back(const_cast<char*>(s.c_str()));
        }

        if (!dynamic_args) {
            if (execve(args_[0].c_str(), (char**) &strs[0], (char**) ENV) < 0) {
                ERROR("cannot execve('%s'): %s\n", args_[0].c_str(), strerror(errno));
            }
        } else {
            char* tmp = strdup(dynamic_args);
            char* next = tmp;
            char* bword;

            while((bword = strsep(&next, " "))) {
                strs.push_back(bword);
            }
            execve(args_[0].c_str(), (char**) &strs[0], (char**) ENV);
        }
        _exit(127);
    }

    free(scon);

    if (pid < 0) {
        ERROR("failed to start '%s'\n", name_.c_str());
        pid_ = 0;
        return;
    }

    time_started_ = gettime();
    pid_ = pid;
    flags_ |= SVC_RUNNING;

    if ((flags_ & SVC_EXEC) != 0) {
        INFO("SVC_EXEC pid %d (uid %d gid %d+%zu context %s) started; waiting...\n",
             pid_, uid_, gid_, nr_supp_gids_,
             !seclabel_.empty() ? seclabel_.c_str() : "default");
        waiting_for_exec = true;
    }

    NotifyStateChange("running");
}

void Service::StartIfNotDisabled()
{
    if (!(flags_ & SVC_DISABLED)) {
        Start(nullptr);
    } else {
        flags_ |= SVC_DISABLED_START;
    }
}

void Service::Enable()
{
    flags_ &= ~(SVC_DISABLED | SVC_RC_DISABLED);
    if (flags_ & SVC_DISABLED_START) {
        Start(nullptr);
    }
}

void Service::Reset()
{
    StopOrReset(SVC_RESET);
}

void Service::Stop()
{
    StopOrReset(SVC_DISABLED);
}

void Service::Restart()
{
    if (flags_ & SVC_RUNNING) {
        /* Stop, wait, then start the service. */
        StopOrReset(SVC_RESTART);
    } else if (!(flags_ & SVC_RESTARTING)) {
        /* Just start the service since it's not running. */
        Start(nullptr);
    } /* else: Service is restarting anyways. */
}

void Service::RestartIfNeeded(time_t process_needs_restart)
{
    time_t next_start_time = time_started_ + 5;

    if (next_start_time <= gettime()) {
        flags_ &= (~SVC_RESTARTING);
        Start(nullptr);
        return;
    }

    if ((next_start_time < process_needs_restart) ||
        (process_needs_restart == 0)) {
        process_needs_restart = next_start_time;
    }
}

/* The how field should be either SVC_DISABLED, SVC_RESET, or SVC_RESTART */
void Service::StopOrReset(int how)
{
    /* The service is still SVC_RUNNING until its process exits, but if it has
     * already exited it shoudn't attempt a restart yet. */
    flags_ &= ~(SVC_RESTARTING | SVC_DISABLED_START);

    if ((how != SVC_DISABLED) && (how != SVC_RESET) && (how != SVC_RESTART)) {
        /* Hrm, an illegal flag.  Default to SVC_DISABLED */
        how = SVC_DISABLED;
    }
        /* if the service has not yet started, prevent
         * it from auto-starting with its class
         */
    if (how == SVC_RESET) {
        flags_ |= (flags_ & SVC_RC_DISABLED) ? SVC_DISABLED : SVC_RESET;
    } else {
        flags_ |= how;
    }

    if (pid_) {
        NOTICE("Service '%s' is being killed...\n", name_.c_str());
        kill(-pid_, SIGKILL);
        NotifyStateChange("stopping");
    } else {
        NotifyStateChange("stopped");
    }
}

int ServiceManager::exec_count = 0;

ServiceManager::ServiceManager()
{
}

ServiceManager& ServiceManager::GetInstance() {
    static ServiceManager instance;
    return instance;
}

Service* ServiceManager::AddNewService(const std::string& name,
                                       const std::string& classname,
                                       const std::vector<std::string>& args,
                                       std::string* err)
{
    if (!ValidName(name)) {
        *err = android::base::StringPrintf("invalid service name '%s'\n", name.c_str());
        return nullptr;
    }

    Service* svc = ServiceManager::GetInstance().ServiceFindByName(name);
    if (svc) {
        *err = android::base::StringPrintf("ignored duplicate definition of service '%s'\n",
                                           name.c_str());
        return nullptr;
    }

    svc = new Service(name, classname, args);
    service_list_.push_back(svc);
    return svc;
}

Service* ServiceManager::MakeExecOneshotService(const std::vector<std::string>& args)
{
    // Parse the arguments: exec [SECLABEL [UID [GID]*] --] COMMAND ARGS...
    // SECLABEL can be a - to denote default
    int command_arg = 1;
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (!args[i].compare("--")) {
            command_arg = i + 1;
            break;
        }
    }
    if (command_arg > 4 + NR_SVC_SUPP_GIDS) {
        ERROR("exec called with too many supplementary group ids\n");
        return nullptr;
    }

    std::vector<std::string> str_args(args.begin() + command_arg, args.end());
    if (str_args.size() < 1) {
        ERROR("exec called without command\n");
        return nullptr;
    }

    std::string ret_err;
    std::string name = android::base::StringPrintf("exec %d - %s", exec_count++, str_args[0].c_str());
    Service* svc = AddNewService(name, "default", args, &ret_err);
    if (!svc) {
        ERROR("Couldn't allocate service for exec of '%s': %s", str_args[0].c_str(), ret_err.c_str());
        return nullptr;
    }

    svc->flags_ = SVC_EXEC | SVC_ONESHOT;

    if (command_arg > 2 && args[1].compare("-")) {
        svc->seclabel_ = args[1];
    }
    if (command_arg > 3) {
        svc->uid_ = decode_uid(args[2].c_str());
    }
    if (command_arg > 4) {
        svc->gid_ = decode_uid(args[3].c_str());
        svc->nr_supp_gids_ = command_arg - 1 /* -- */ - 4 /* exec SECLABEL UID GID */;
        for (size_t i = 0; i < svc->nr_supp_gids_; ++i) {
            svc->supp_gids_[i] = decode_uid(args[4 + i].c_str());
        }
    }

    return svc;
}

Service* ServiceManager::ServiceFindByName(const std::string& name)
{
    auto svc = std::find_if(service_list_.begin(), service_list_.end(),
                            [&name] (Service* s)
                            { return !name.compare(s->get_name()); });
    if (svc != service_list_.end()) {
        return *svc;
    }
    return nullptr;
}

Service* ServiceManager::ServiceFindByPid(pid_t pid)
{
    auto svc = std::find_if(service_list_.begin(), service_list_.end(),
                            [&pid] (Service* s) { return s->get_pid() == pid; });
    if (svc != service_list_.end()) {
        return *svc;
    }
    return nullptr;
}

Service* ServiceManager::ServiceFindByKeychord(int keychord_id)
{
    auto svc = std::find_if(service_list_.begin(), service_list_.end(),
                            [&keychord_id] (Service* s)
                            { return s->get_keychord_id() == keychord_id; });

    if (svc != service_list_.end()) {
        return *svc;
    }
    return nullptr;
}

void ServiceManager::ServiceForEach(void (*func)(Service* svc))
{
    for (auto& s : service_list_) {
        func(s);
    }
}

void ServiceManager::ServiceForEachClass(const std::string& classname,
                                         void (*func)(Service* svc))
{
    for (auto& s : service_list_) {
        if (!classname.compare(s->get_classname())) {
            func(s);
        }
    }
}

void ServiceManager::ServiceForEachFlags(unsigned matchflags,
                                         void (*func)(Service* svc))
{
    for (auto& s : service_list_) {
        if (s->get_flags() == matchflags) {
            func(s);
        }
    }
}

void ServiceManager::RemoveService(const Service& svc)
{
    auto svc_it = std::find_if(service_list_.begin(), service_list_.end(),
                               [&svc] (Service* s) { return !svc.get_name().compare(s->get_name()); });
    if (svc_it == service_list_.end()) {
        return;
    }

    service_list_.erase(svc_it);
}

bool ServiceManager::ValidName(const std::string& name)
{
    if (name.size() > 16) {
        return false;
    }
    for (const auto& c : name) {
        if (!isalnum(c) && (c != '_') && (c != '-')) {
            return false;
        }
    }
    return true;
}

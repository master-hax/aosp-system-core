/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include "signal_handler.h"

#include <signal.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <android-base/chrono_utils.h>
#include <android-base/logging.h>
#include <android-base/scopeguard.h>
#include <android-base/stringprintf.h>

#include "init.h"
#include "property_service.h"
#include "reboot.h"
#include "service.h"

using android::base::StringPrintf;
using android::base::boot_clock;
using android::base::make_scope_guard;

namespace android {
namespace init {

static int signal_write_fd = -1;
static int signal_read_fd = -1;

static void HandleSigterm(struct signalfd_siginfo* siginfo);

static bool ReapOneProcess() {
    siginfo_t siginfo = {};
    // This returns a zombie pid or informs us that there are no zombies left to be reaped.
    // It does NOT reap the pid; that is done below.
    if (TEMP_FAILURE_RETRY(waitid(P_ALL, 0, &siginfo, WEXITED | WNOHANG | WNOWAIT)) != 0) {
        PLOG(ERROR) << "waitid failed";
        return false;
    }

    auto pid = siginfo.si_pid;
    if (pid == 0) return false;

    // At this point we know we have a zombie pid, so we use this scopeguard to reap the pid
    // whenever the function returns from this point forward.
    // We do NOT want to reap the zombie earlier as in Service::Reap(), we kill(-pid, ...) and we
    // want the pid to remain valid throughout that (and potentially future) usages.
    auto reaper = make_scope_guard([pid] { TEMP_FAILURE_RETRY(waitpid(pid, nullptr, WNOHANG)); });

    if (PropertyChildReap(pid)) return true;

    Service* service = ServiceList::GetInstance().FindService(pid, &Service::pid);

    std::string name;
    std::string wait_string;
    if (service) {
        name = StringPrintf("Service '%s' (pid %d)", service->name().c_str(), pid);
        if (service->flags() & SVC_EXEC) {
            auto exec_duration = boot_clock::now() - service->time_started();
            auto exec_duration_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(exec_duration).count();
            wait_string = StringPrintf(" waiting took %f seconds", exec_duration_ms / 1000.0f);
        }
    } else {
        name = StringPrintf("Untracked pid %d", pid);
    }

    auto status = siginfo.si_status;
    if (WIFEXITED(status)) {
        LOG(INFO) << name << " exited with status " << WEXITSTATUS(status) << wait_string;
    } else if (WIFSIGNALED(status)) {
        LOG(INFO) << name << " killed by signal " << WTERMSIG(status) << wait_string;
    }

    if (!service) return true;

    service->Reap();

    if (service->flags() & SVC_TEMPORARY) {
        ServiceList::GetInstance().RemoveService(*service);
    }

    return true;
}

static void handle_signal() {
    struct signalfd_siginfo siginfo;
    ssize_t bytes_read = TEMP_FAILURE_RETRY(read(signal_read_fd, &siginfo, sizeof(siginfo)));
    if (bytes_read != sizeof(siginfo)) {
        // Even if we failed to read the whole information about the signal, we
        // still want to reap any outstanding children.
        ReapAnyOutstandingChildren();
        return;
    }

    switch (siginfo.ssi_signo) {
        case SIGCHLD:
            ReapAnyOutstandingChildren();
            break;

        case SIGTERM:
            HandleSigterm(&siginfo);
            break;
    }
}

static void signal_handler(int, siginfo_t* siginfo, void*) {
    if (TEMP_FAILURE_RETRY(write(signal_write_fd, siginfo, sizeof(siginfo_t))) == -1) {
        PLOG(ERROR) << "write(signal_write_fd) failed";
    }
}

void ReapAnyOutstandingChildren() {
    while (ReapOneProcess()) {
    }
}

static void HandleSigterm(struct signalfd_siginfo* siginfo) {
    if (siginfo->ssi_pid != 0) {
        // Drop any userspace SIGTERM requests.
        LOG(DEBUG) << "Ignoring SIGTERM from pid " << siginfo->ssi_pid;
        return;
    }

    HandlePowerctlMessage("shutdown");
}

void signal_handler_init() {
    // Create a signalling mechanism for SIGCHLD.
    int s[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, s) == -1) {
        PLOG(ERROR) << "socketpair failed";
        exit(1);
    }

    signal_write_fd = s[0];
    signal_read_fd = s[1];

    // Write to signal_write_fd if we catch SIGCHLD.
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = signal_handler;
    act.sa_flags = SA_NOCLDSTOP | SA_SIGINFO;
    sigaction(SIGCHLD, &act, nullptr);

    // Also write to signal_write_fd if we catch SIGTERM.
    if (ALLOW_HANDLING_SIGTERM) {
        memset(&act, 0, sizeof(act));
        act.sa_sigaction = signal_handler;
        act.sa_flags = SA_SIGINFO;
        sigaction(SIGTERM, &act, nullptr);
    }

    ReapAnyOutstandingChildren();

    register_epoll_handler(signal_read_fd, handle_signal);
}

}  // namespace init
}  // namespace android

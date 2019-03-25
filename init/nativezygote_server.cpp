/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "nativezygote_server.h"

#include <android/dlext.h>
#include <linux/securebits.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bitset>
#include <set>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/iosched_policy.h>
#include <cutils/sockets.h>
#include <log/log.h>
#include <processgroup/processgroup.h>
#include <selinux/android.h>

#include "capabilities.h"
#include "descriptors.h"
#include "result.h"
#include "selabel.h"
#include "service_utils.h"
#include "util.h"

using android::base::GetProperty;
using android::base::StartsWith;
using android::base::StringPrintf;
using android::base::unique_fd;
using android::base::WriteStringToFile;

namespace android {
namespace init {

namespace {

// Helper function to in-place determine the basename of a path.
const char* Basename(const char* path) {
    const char* basename = path;
    for (; *path; ++path) {
        if (*path == '/') {
            basename = path + 1;
        }
    }
    return basename;
}

}  // namespace

NativeZygoteServer::NativeZygoteServer(const char* socket_name) {
    ctrl_sock_ = android_get_control_socket(socket_name);
    if (ctrl_sock_ < 0) {
        LOG(FATAL) << "Failed to get control socket " << socket_name;
    }
    if (listen(ctrl_sock_, 1) < 0) {
        PLOG(FATAL) << "Failed to listen on control socket " << socket_name;
    }

    data_sock_ = -1;

    SelabelInitialize();
}

void NativeZygoteServer::MainLoop() {
    poll_fds_[0].fd = ctrl_sock_;
    poll_fds_[0].events = POLLIN;
    poll_fds_[1].fd = -1;
    poll_fds_[1].events = POLLIN;
    nfds_ = 1;

    while (true) {
        if (TEMP_FAILURE_RETRY(poll(poll_fds_, nfds_, -1)) < 0) {
            PLOG(ERROR) << "Error on poll()";
            continue;
        }

        for (size_t i = 0; i < nfds_; ++i) {
            if (poll_fds_[i].revents & POLLERR) {
                LOG(DEBUG) << "POLLERR on " << (i == 0 ? "control" : "data") << " socket";
            }
            if (poll_fds_[i].revents & POLLNVAL) {
                LOG(ERROR) << "POLLNVAL on " << (i == 0 ? "control" : "data") << " socket";
            }
        }

        if (poll_fds_[0].revents & POLLHUP) {
            LOG(FATAL) << "Connection from init was dropped";
        }

        if (data_sock_ > 0) {
            if (poll_fds_[1].revents & POLLIN) {
                HandleRequest();
            }
            if (poll_fds_[1].revents & POLLHUP) {
                CloseDataSocket();
            }
        }

        if (poll_fds_[0].revents & POLLIN) {
            HandleConnection();
        }
    }
}

bool NativeZygoteServer::ReadRequest() {
    std::string buf(kMaxNativeZygoteRequestSize, '\0');
    size_t data_size = TEMP_FAILURE_RETRY(read(data_sock_, &buf[0], kMaxNativeZygoteRequestSize));
    if (data_size < 0) {
        PLOG(ERROR) << "failed to receive request";
        return false;
    }
    buf.resize(data_size);

    if (!req_.ParseFromString(buf)) {
        LOG(ERROR) << "failed to deserialize request";
        return false;
    }
    return true;
}

void NativeZygoteServer::HandleRequest() {
    if (!ReadRequest()) {
        return;
    }

    auto flags = req_.namespace_flags() | SIGCHLD;
    if (!(flags & (CLONE_NEWPID | CLONE_NEWUSER))) {
        flags |= CLONE_PARENT;
    }
    pid_t pid = clone(nullptr, nullptr, flags, nullptr);
    if (pid == 0) {
        CloseAllSockets();
        LOG(INFO) << "Starting service: " << req_.name();
        Specialize();
    } else {
        if (TEMP_FAILURE_RETRY(write(data_sock_, &pid, sizeof(pid))) < 0) {
            PLOG(ERROR) << "failed to report PID for " << req_.name();
        }
    }
}

void NativeZygoteServer::CloseAllSockets() {
    close(ctrl_sock_);
    if (data_sock_ != -1) {
        close(data_sock_);
    }
}

std::set<int> NativeZygoteServer::GetFileDescriptors() {
    auto proc_fd_dir =
            std::unique_ptr<DIR, decltype(&closedir)>{opendir("/proc/self/fd"), closedir};
    if (!proc_fd_dir) {
        PLOG(FATAL) << "Failed to open /proc/self/fd";
    }

    int dir_fd = dirfd(proc_fd_dir.get());
    dirent* dir_entry;
    std::set<int> fds;
    while ((dir_entry = readdir(proc_fd_dir.get())) != nullptr) {
        char* end;
        const int fd = strtol(dir_entry->d_name, &end, 10);
        if (*end != '\0') {
            continue;
        }
        if (fd <= STDERR_FILENO || fd == dir_fd) {
            continue;
        }
        fds.insert(fd);
    }

    return fds;
}

void NativeZygoteServer::CloseDataSocket() {
    if (data_sock_ > 0) {
        close(data_sock_);
        --nfds_;
        poll_fds_[1].fd = -1;
        data_sock_ = -1;
    }
}

void NativeZygoteServer::HandleConnection() {
    // We only expect one client.  Drop existing client if any.
    CloseDataSocket();
    data_sock_ = TEMP_FAILURE_RETRY(accept(ctrl_sock_, nullptr, nullptr));
    if (data_sock_ > 0) {
        poll_fds_[1].fd = data_sock_;
        ++nfds_;
    }
}

std::set<int> NativeZygoteServer::CreateAndPublishDescriptors() {
    std::set<int> fds;
    for (auto const& desc_info : req_.descriptors()) {
        auto desc_class =
                static_cast<DescriptorInfo::DescriptorClass>(desc_info.descriptor_class());
        if (desc_class == DescriptorInfo::DescriptorClass::DESCRIPTOR_CLASS_SOCKET) {
            SocketInfo desc(desc_info.name(), desc_info.type(), desc_info.uid(), desc_info.gid(),
                            desc_info.perm(), desc_info.context());
            int fd = desc.CreateAndPublish(req_.scon());
            if (fd >= 0) {
                fds.insert(fd);
            }
        } else if (desc_class == DescriptorInfo::DescriptorClass::DESCRIPTOR_CLASS_FILE) {
            FileInfo desc(desc_info.name(), desc_info.type(), desc_info.uid(), desc_info.gid(),
                          desc_info.perm(), desc_info.context());
            int fd = desc.CreateAndPublish(req_.scon());
            if (fd >= 0) {
                fds.insert(fd);
            }
        } else {
            LOG(FATAL) << "Unknown descriptor class: " << desc_info.descriptor_class();
        }
    }
    return fds;
}

std::vector<char*> NativeZygoteServer::ExpandArgsAndSetCmdline() {
    // Buffer storing command line arguments.  This needs to survive for the
    // entirety of the process lifetime, because the kernel reads this directly.
    // Therefore, we make it static.
    static std::string buf;
    buf.clear();

    std::vector<size_t> arg_positions;
    arg_positions.push_back(0);
    buf += req_.args(0) + '\0';
    for (size_t i = 1; i < req_.args_size(); ++i) {
        std::string expanded;
        if (!expand_props(req_.args(i), &expanded)) {
            LOG(FATAL) << req_.args(0) << ": cannot expand '" << req_.args(i) << "'";
        }
        arg_positions.push_back(buf.size());
        buf += expanded + '\0';
    }

    std::vector<char*> expanded_args;
    for (size_t pos : arg_positions) {
        expanded_args.push_back(buf.data() + pos);
    }
    expanded_args.push_back(nullptr);

    // Set /proc/self/cmdline
    if (prctl(PR_SET_MM, PR_SET_MM_ARG_START, buf.data(), 0, 0) < 0) {
        if (prctl(PR_SET_MM, PR_SET_MM_ARG_END, buf.data() + buf.size(), 0, 0) < 0 ||
            prctl(PR_SET_MM, PR_SET_MM_ARG_START, buf.data(), 0, 0) < 0) {
            PLOG(ERROR) << req_.args(0) << ": cannot set cmdline";
        }
    } else {
        if (prctl(PR_SET_MM, PR_SET_MM_ARG_END, buf.data() + buf.size(), 0, 0) < 0) {
            PLOG(ERROR) << req_.args(0) << ": cannot set cmdline";
        }
    }

    // Set /proc/self/comm
    if (prctl(PR_SET_NAME, Basename(expanded_args[0]), 0, 0, 0) < 0) {
        PLOG(ERROR) << req_.args(0) << ": cannot set process name";
    }

    return expanded_args;
}

void NativeZygoteServer::SetProcessAttributesAndCaps() {
    // Keep capabilities before setting uid.
    unsigned long securebits = prctl(PR_GET_SECUREBITS);
    if (securebits == -1UL) {
        PLOG(FATAL) << "prctl(PR_GET_SECUREBITS) failed for " << req_.name();
    }
    securebits |= SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP;
    if (prctl(PR_SET_SECUREBITS, securebits) != 0) {
        PLOG(FATAL) << "prctl(PR_SET_SECUREBITS) failed for " << req_.name();
    }

    ProcessAttributes attr;
    attr.console = req_.console();
    attr.ioprio_class = static_cast<IoSchedClass>(req_.ioprio_class());
    attr.ioprio_pri = req_.ioprio_pri();
    for (const auto& rlimit_param : req_.rlimits()) {
        rlimit rlim;
        rlim.rlim_cur = rlimit_param.rlim_cur();
        rlim.rlim_max = rlimit_param.rlim_max();
        attr.rlimits.push_back(std::make_pair(rlimit_param.type(), rlim));
    }
    attr.uid = req_.uid();
    attr.gid = req_.gid();
    for (const auto& gid : req_.supp_gids()) {
        attr.supp_gids.push_back(gid);
    }
    attr.priority = req_.priority();
    if (auto result = SetProcessAttributes(attr); !result) {
        LOG(FATAL) << "cannot set attribute for " << req_.name() << ": " << result.error();
    }

    // Clear securebits we set before.
    securebits &= ~(SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP);
    if (prctl(PR_SET_SECUREBITS, securebits) != 0) {
        PLOG(FATAL) << "prctl(PR_SET_SECUREBITS) failed for " << req_.name();
    }

    if (req_.has_cap_set()) {
        if (!SetCapsForExec(CapSet(req_.cap_set()), true)) {
            LOG(FATAL) << "cannot set capabilities for " << req_.name();
        }
    } else if (req_.uid()) {
        if (!SetCapsForExec(CapSet(), true)) {
            LOG(FATAL) << "cannot drop capabilities for " << req_.name();
        }
    }

    if (selinux_android_setcon(req_.scon().c_str()) != 0) {
        PLOG(FATAL) << "cannot setcon('" << req_.scon() << "') for " << req_.name();
    }
}

void NativeZygoteServer::Specialize() {
    // A major part of this function and functions associated with it are
    // similar to what is in service.cpp.  We chose to duplicate the code
    // because we want to eventually deprecate native zygote, and refactoring
    // this and reverting later seem more trouble than it's worth.
    // TODO(victoryang): If native zygote stays around, refactor this to reduce
    //                   duplication.

    // Closing the log fd early so that we don't get a SELinux error when trying
    // to close after changing security context.  Note that we do attempt to
    // close this again before jumping to target so that if at any point after
    // here we log an error, the reacquired log resources will be released (but
    // with some SELinux spam).
    __android_log_close();

    umask(077);

    NamespaceInfo info;
    info.flags = req_.namespace_flags();
    for (const auto& ns_to_enter : req_.namespaces_to_enter()) {
        info.namespaces_to_enter.push_back(
                std::make_pair(ns_to_enter.nstype(), ns_to_enter.path()));
    }

    if (auto result = EnterNamespaces(info, req_.name(), false); !result) {
        LOG(FATAL) << "Service '" << req_.name()
                   << "' failed to set up namespaces: " << result.error();
    }

    for (auto const& env_var : req_.env_vars()) {
        setenv(env_var.key().c_str(), env_var.value().c_str(), 1);
    }

    auto const fds = CreateAndPublishDescriptors();

    std::vector<std::string> writepid_files(req_.writepid_files().begin(),
                                            req_.writepid_files().end());
    if (auto result = WritePidToFiles(&writepid_files); !result) {
        LOG(ERROR) << "failed to write pid to files: " << result.error();
    }
    writepid_files.clear();

    // Set command lines before setting process attributes so that this succeeds
    // regardless of the capability and the security permission of the target
    // executable.
    std::vector<char*> expanded_args = ExpandArgsAndSetCmdline();

    SetProcessAttributesAndCaps();

    __android_log_close();

    // Leaking file descriptors to the specialized process can cause security
    // issues or hard-to-debug bugs.  Before loading the target executable,
    // make sure only file descriptors requested by init are open.
    if (GetFileDescriptors() != fds) {
        LOG(FATAL) << "Unexpect file descriptor left open after specializing";
    }

    if (req_.sigstop()) {
        kill(getpid(), SIGSTOP);
    }

    android_run_executable(expanded_args[0], expanded_args.data());

    _exit(127);
}

}  // namespace init
}  // namespace android

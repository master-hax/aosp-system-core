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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <android/dlext.h>
#include <cutils/iosched_policy.h>
#include <cutils/sockets.h>
#include <linux/securebits.h>
#include <log/log.h>
#include <processgroup/processgroup.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bitset>
#include <string>
#include <vector>

#include "descriptors.h"
#include "result.h"
#include "util.h"

#ifdef _INIT_INIT_H
#error "Do not include init.h in files used by nativezygote; it will expose init's globals"
#endif

using android::base::GetProperty;
using android::base::StartsWith;
using android::base::StringPrintf;
using android::base::unique_fd;
using android::base::WriteStringToFile;

namespace android {
namespace init {

namespace {

using CapSet = std::bitset<CAP_LAST_CAP + 1>;

// A helper class to construct the command line argument storage for use with
// prctl PR_SET_MM.
class ContigiousStringStore {
  public:
    // Appends the given string at the end of the buffer and return the start
    // position of the appended string.  Note that we return the index instead
    // of a pointer because later calls to Add() may cause the entire buffer
    // to be relocated.
    size_t Add(std::string const& str) {
        size_t ret = buf_.size();
        buf_ += str;
        buf_.push_back('\0');
        return ret;
    }

    void Clear() { buf_.clear(); }

    char* Begin() { return buf_.data(); }
    char* End() { return buf_.data() + buf_.size(); }

  private:
    std::string buf_;
};

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

// Perform double fork.  The end result is similar to fork() but the child
// process has PID 1.  If namespace_flags is non-zero, use clone() with the
// given flags instead of fork().
pid_t DoubleFork(int namespace_flags) {
    // Create a pipe for the child process to report to the parent the PID of the
    // grandchild process.
    unique_fd pipe_read, pipe_write;
    if (!android::base::Pipe(&pipe_read, &pipe_write)) {
        PLOG(ERROR) << "Failed to open a pipe for double fork";
        return -1;
    }

    pid_t child_pid = clone(nullptr, nullptr, 0, nullptr);
    if (child_pid == 0) {
        pid_t grandchild_pid;
        if (namespace_flags) {
            grandchild_pid = clone(nullptr, nullptr, namespace_flags | SIGCHLD, nullptr);
        } else {
            grandchild_pid = fork();
        }

        if (grandchild_pid == 0) {
            // Grandchild process.
            return 0;
        } else {
            // Child process. Its only responsibility is to fork report the PID
            // of the grandchild process to the parent.
            write(pipe_write.get(), &grandchild_pid, sizeof(grandchild_pid));
            _exit(0);
        }
    } else {
        // Parent.
        pid_t grandchild_pid;
        read(pipe_read.get(), &grandchild_pid, sizeof(grandchild_pid));
        return grandchild_pid;
    }
}

Result<Success> SetCapabilities(CapSet const& cap_set) {
    cap_t c = cap_init();
    cap_value_t value[1];
    for (int cap = 0; cap < cap_set.size(); ++cap) {
        if (cap_set.test(cap)) {
            value[0] = cap;
            if (cap_set_flag(c, CAP_INHERITABLE, 1, value, CAP_SET) != 0 ||
                cap_set_flag(c, CAP_PERMITTED, 1, value, CAP_SET) != 0 ||
                cap_set_flag(c, CAP_EFFECTIVE, 1, value, CAP_SET) != 0) {
                return ErrnoError() << "Cannot set capability " << cap;
            }
        } else {
            if (cap_drop_bound(cap) == -1) {
                return ErrnoError() << "Cannot drop capability " << cap;
            }
        }
    }
    if (cap_set_proc(c) == -1) {
        return ErrnoError() << "Cannot apply capability change";
    }
    cap_free(c);
    for (int cap = 0; cap < cap_set.size(); ++cap) {
        if (cap_set.test(cap)) {
            if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) == -1) {
                return ErrnoError() << "Cannot raise ambient capability " << cap;
            }
        }
    }
    return Success();
}

}  // namespace

NativeZygoteServer::NativeZygoteServer(const char* socket_name) {
    ctrl_sock_ = android_get_control_socket(socket_name);
    if (ctrl_sock_ == -1) {
        LOG(FATAL) << "Failed to get control socket " << socket_name;
    }
    if (listen(ctrl_sock_, 1) == -1) {
        PLOG(FATAL) << "Failed to listen on control socket " << socket_name;
    }

    data_sock_ = -1;
}

void NativeZygoteServer::MainLoop() {
    while (true) {
        int nfds = ctrl_sock_;
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctrl_sock_, &rfds);
        if (data_sock_ != -1) {
            if (data_sock_ > nfds) {
                nfds = data_sock_;
            }
            FD_SET(data_sock_, &rfds);
        }
        if (select(nfds + 1, &rfds, nullptr, nullptr, nullptr) == -1) {
            if (errno != EINTR) {
                PLOG(ERROR) << "Error on select()";
            }
            continue;
        }

        if (data_sock_ != -1) {
            if (FD_ISSET(data_sock_, &rfds)) {
                HandleRequest();
            }
        }
        if (FD_ISSET(ctrl_sock_, &rfds)) {
            HandleConnection();
        }
    }
}

bool NativeZygoteServer::ReadRequest() {
    std::string buf(kMaxNativeZygoteRequestSize, '\0');
    size_t data_size = read(data_sock_, &buf[0], kMaxNativeZygoteRequestSize);
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

    pid_t pid = DoubleFork(req_.namespace_flags());
    if (pid == 0) {
        CloseSockets();
        LOG(INFO) << "Starting service: " << req_.name();
        Specialize();
    } else {
        write(data_sock_, &pid, sizeof(pid));
    }
}

void NativeZygoteServer::CloseSockets() {
    close(ctrl_sock_);
    if (data_sock_ != -1) {
        close(data_sock_);
    }
}

size_t NativeZygoteServer::GetFileDescriptorCount() {
    DIR* proc_fd_dir = opendir("/proc/self/fd");
    if (proc_fd_dir == nullptr) {
        PLOG(FATAL) << "Failed to open /proc/self/fd";
    }

    int dir_fd = dirfd(proc_fd_dir);
    dirent* dir_entry;
    size_t fd_count = 0;
    while ((dir_entry = readdir(proc_fd_dir)) != nullptr) {
        char* end;
        const int fd = strtol(dir_entry->d_name, &end, 10);
        if (*end != '\0') {
            continue;
        }
        if (fd <= STDERR_FILENO || fd == dir_fd) {
            continue;
        }
        ++fd_count;
    }
    if (closedir(proc_fd_dir) == -1) {
        PLOG(FATAL) << "Failed to close /proc/self/fd";
    }

    return fd_count;
}

void NativeZygoteServer::HandleConnection() {
    // We only expect one client.  Drop existing client if any.
    if (data_sock_ != -1) {
        close(data_sock_);
    }
    data_sock_ = accept(ctrl_sock_, nullptr, nullptr);
}

Result<Success> NativeZygoteServer::EnterNamespaces() {
    for (auto const& ns_to_enter : req_.namespaces_to_enter()) {
        auto fd = unique_fd(open(ns_to_enter.path().c_str(), O_RDONLY | O_CLOEXEC));
        if (fd == -1) {
            return ErrnoError() << "Could not open namespace at " << ns_to_enter.path();
        }
        if (setns(fd.get(), ns_to_enter.nstype()) == -1) {
            return ErrnoError() << "Could not setns() namespace at " << ns_to_enter.path();
        }
    }
    return Success();
}

Result<Success> NativeZygoteServer::SetUpMountNamespace() {
    constexpr unsigned int kSafeFlags = MS_NODEV | MS_NOEXEC | MS_NOSUID;

    // Recursively remount / as slave like zygote does so unmounting and mounting /proc
    // doesn't interfere with the parent namespace's /proc mount. This will also
    // prevent any other mounts/unmounts initiated by the service from interfering
    // with the parent namespace but will still allow mount events from the parent
    // namespace to propagate to the child.
    if (mount("rootfs", "/", nullptr, (MS_SLAVE | MS_REC), nullptr) == -1) {
        return ErrnoError() << "Could not remount(/) recursively as slave";
    }

    // umount() then mount() /proc and/or /sys
    // Note that it is not sufficient to mount with MS_REMOUNT.
    if (req_.namespace_flags() & CLONE_NEWPID) {
        if (umount("/proc") == -1) {
            return ErrnoError() << "Could not umount(/proc)";
        }
        if (mount("", "/proc", "proc", kSafeFlags, "") == -1) {
            return ErrnoError() << "Could not mount(/proc)";
        }
    }
    bool remount_sys =
            std::any_of(req_.namespaces_to_enter().begin(), req_.namespaces_to_enter().end(),
                        [](const auto& entry) { return entry.nstype() == CLONE_NEWNET; });
    if (remount_sys) {
        if (umount2("/sys", MNT_DETACH) == -1) {
            return ErrnoError() << "Could not umount(/sys)";
        }
        if (mount("", "/sys", "sysfs", kSafeFlags, "") == -1) {
            return ErrnoError() << "Could not mount(/sys)";
        }
    }
    return Success();
}

Result<Success> NativeZygoteServer::SetUpPidNamespace() {
    if (prctl(PR_SET_NAME, req_.name().c_str()) == -1) {
        return ErrnoError() << "Could not set name";
    }

    pid_t child_pid = fork();
    if (child_pid == -1) {
        return ErrnoError() << "Could not fork inside the PID namespace";
    }

    if (child_pid > 0) {
        // So that we exit with the right status.
        static int init_exitstatus = 0;
        signal(SIGTERM, [](int) { _exit(init_exitstatus); });

        pid_t waited_pid;
        int status;
        while ((waited_pid = wait(&status)) > 0) {
            // This loop will end when there are no processes left inside the
            // PID namespace or when the init process inside the PID namespace
            // gets a signal.
            if (waited_pid == child_pid) {
                init_exitstatus = status;
            }
        }
        if (!WIFEXITED(init_exitstatus)) {
            _exit(EXIT_FAILURE);
        }
        _exit(WEXITSTATUS(init_exitstatus));
    }
    return Success();
}

void NativeZygoteServer::CreateAndPublishDescriptors() {
    for (auto const& desc_info : req_.descriptors()) {
        auto desc_class =
                static_cast<DescriptorInfo::DescriptorClass>(desc_info.descriptor_class());
        if (desc_class == DescriptorInfo::DescriptorClass::DESCRIPTOR_CLASS_SOCKET) {
            auto desc = new SocketInfo(desc_info.name(), desc_info.type(), desc_info.uid(),
                                       desc_info.gid(), desc_info.perm(), desc_info.context());
            desc->CreateAndPublish(req_.scon());
        } else if (desc_class == DescriptorInfo::DescriptorClass::DESCRIPTOR_CLASS_FILE) {
            auto desc = new FileInfo(desc_info.name(), desc_info.type(), desc_info.uid(),
                                     desc_info.gid(), desc_info.perm(), desc_info.context());
            desc->CreateAndPublish(req_.scon());
        } else {
            LOG(FATAL) << "Unknown descriptor class: " << desc_info.descriptor_class();
        }
    }
}

void NativeZygoteServer::WritePidToFiles() {
    std::string const pid_str = std::to_string(getpid());
    std::string cpuset_path;
    if (CgroupGetControllerPath("cpuset", &cpuset_path)) {
        auto cpuset_predicate = [&cpuset_path](const std::string& path) {
            return StartsWith(path, cpuset_path + "/");
        };
        auto iter = std::find_if(req_.writepid_files().begin(), req_.writepid_files().end(),
                                 cpuset_predicate);
        if (iter == req_.writepid_files().end()) {
            // There were no "writepid" instructions for cpusets, check if the
            // system default cpuset is specified to be used for the process.
            std::string default_cpuset = GetProperty("ro.cpuset.default", "");
            if (!default_cpuset.empty()) {
                // Make sure the cpuset name starts and ends with '/'.
                // A single '/' means the 'root' cpuset.
                if (default_cpuset.front() != '/') {
                    default_cpuset.insert(0, 1, '/');
                }
                if (default_cpuset.back() != '/') {
                    default_cpuset.push_back('/');
                }
                if (!WriteStringToFile(pid_str, StringPrintf("%s%stasks", cpuset_path.c_str(),
                                                             default_cpuset.c_str()))) {
                    PLOG(ERROR) << "couldn't write " << pid_str << " to cpuset";
                }
            }
        }
    } else {
        LOG(ERROR) << "cpuset cgroup controller is not mounted!";
    }
    for (const auto& file : req_.writepid_files()) {
        if (!WriteStringToFile(pid_str, file)) {
            PLOG(ERROR) << "couldn't write " << pid_str << " to " << file;
        }
    }
}

std::vector<char*> NativeZygoteServer::ExpandArgsAndSetCmdline() {
    // Buffer storing command line arguments.  This needs to survive for the
    // entirety of the process lifetime, so we make it static.
    static ContigiousStringStore buf;
    buf.Clear();

    std::vector<size_t> arg_positions;
    arg_positions.push_back(buf.Add(req_.args(0)));
    for (size_t i = 1; i < req_.args_size(); ++i) {
        std::string expanded;
        if (!expand_props(req_.args(i), &expanded)) {
            LOG(FATAL) << req_.args(0) << ": cannot expand '" << req_.args(i) << "'";
        }
        arg_positions.push_back(buf.Add(expanded));
    }

    std::vector<char*> expanded_args;
    for (size_t pos : arg_positions) {
        expanded_args.push_back(buf.Begin() + pos);
    }
    expanded_args.push_back(nullptr);

    // Set /proc/self/cmdline
    if (prctl(PR_SET_MM, PR_SET_MM_ARG_START, buf.Begin(), 0, 0) < 0) {
        if (prctl(PR_SET_MM, PR_SET_MM_ARG_END, buf.End(), 0, 0) == -1 ||
            prctl(PR_SET_MM, PR_SET_MM_ARG_START, buf.Begin(), 0, 0) == -1) {
            PLOG(ERROR) << req_.args(0) << ": cannot set cmdline";
        }
    } else {
        if (prctl(PR_SET_MM, PR_SET_MM_ARG_END, buf.End(), 0, 0) == -1) {
            PLOG(ERROR) << req_.args(0) << ": cannot set cmdline";
        }
    }

    // Set /proc/self/comm
    if (prctl(PR_SET_NAME, Basename(expanded_args[0]), 0, 0, 0) == -1) {
        PLOG(ERROR) << req_.args(0) << ": cannot set process name";
    }

    return expanded_args;
}

void NativeZygoteServer::SetProcessAttributes() {
    for (const auto& rlimit_param : req_.rlimits()) {
        rlimit rlim;
        rlim.rlim_cur = rlimit_param.rlim_cur();
        rlim.rlim_max = rlimit_param.rlim_max();
        if (setrlimit(rlimit_param.type(), &rlim) == -1) {
            LOG(FATAL) << StringPrintf("setrlimit(%d, {rlim_cur=%llu, rlim_max=%llu}) failed",
                                       rlimit_param.type(), rlimit_param.rlim_cur(),
                                       rlimit_param.rlim_max());
        }
    }

    // Keep capabilities before setting uid.
    unsigned long securebits = prctl(PR_GET_SECUREBITS);
    if (securebits == -1UL) {
        PLOG(FATAL) << "prctl(PR_GET_SECUREBITS) failed for " << req_.name();
    }
    securebits |= SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP;
    if (prctl(PR_SET_SECUREBITS, securebits) != 0) {
        PLOG(FATAL) << "prctl(PR_SET_SECUREBITS) failed for " << req_.name();
    }

    if (setpgid(0, getpid()) == -1) {
        PLOG(ERROR) << "setpgid failed for " << req_.name();
    }

    if (req_.gid()) {
        if (setgid(req_.gid()) != 0) {
            PLOG(FATAL) << "setgid failed for " << req_.name();
        }
    }

    std::vector<gid_t> supp_gids;
    for (auto gid : req_.supp_gids()) {
        supp_gids.push_back(static_cast<gid_t>(gid));
    }
    if (setgroups(supp_gids.size(), &supp_gids[0]) != 0) {
        PLOG(FATAL) << "setgroups failed for " << req_.name();
    }

    if (req_.uid()) {
        if (setuid(req_.uid()) != 0) {
            PLOG(FATAL) << "setuid failed for " << req_.name();
        }
    }

    // Clear securebits we set before.
    securebits &= ~(SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP);
    if (prctl(PR_SET_SECUREBITS, securebits) != 0) {
        PLOG(FATAL) << "prctl(PR_SET_SECUREBITS) failed for " << req_.name();
    }

    if (req_.priority() != 0) {
        if (setpriority(PRIO_PROCESS, 0, req_.priority()) != 0) {
            PLOG(FATAL) << "setpriority failed for " << req_.name();
        }
    }

    if (req_.has_cap_set()) {
        if (auto result = SetCapabilities(CapSet(req_.cap_set())); !result) {
            LOG(FATAL) << "Service '" << req_.name()
                       << "' could not set capabilities: " << result.error();
        }
    } else if (req_.uid()) {
        if (auto result = SetCapabilities(CapSet()); !result) {
            LOG(FATAL) << "Service '" << req_.name()
                       << "' could not drop capabilities: " << result.error();
        }
    }

    if (setcon(req_.scon().c_str()) != 0) {
        PLOG(FATAL) << "cannot setcon('" << req_.scon() << "') for " << req_.name();
    }
}

void NativeZygoteServer::Specialize() {
    umask(077);

    if (auto result = EnterNamespaces(); !result) {
        LOG(FATAL) << "Service '" << req_.name()
                   << "' could not enter namespaces: " << result.error();
    }

    if (req_.namespace_flags() & CLONE_NEWNS) {
        if (auto result = SetUpMountNamespace(); !result) {
            LOG(FATAL) << "Service '" << req_.name()
                       << "' could not set up mount namespace: " << result.error();
        }
    }

    if (req_.namespace_flags() & CLONE_NEWPID) {
        // This will fork again to run a nativezygote process inside the PID
        // namespace.
        if (auto result = SetUpPidNamespace(); !result) {
            LOG(FATAL) << "Service '" << req_.name()
                       << "' could not set up PID namespace: " << result.error();
        }
    }

    for (auto const& env_var : req_.env_vars()) {
        setenv(env_var.key().c_str(), env_var.value().c_str(), 1);
    }

    CreateAndPublishDescriptors();

    WritePidToFiles();

    if (req_.ioprio_class() != IoSchedClass_NONE) {
        if (android_set_ioprio(getpid(), static_cast<IoSchedClass>(req_.ioprio_class()),
                               req_.ioprio_pri())) {
            PLOG(ERROR) << "failed to set pid " << getpid() << " ioprio=" << req_.ioprio_class()
                        << "," << req_.ioprio_pri();
        }
    }

    if (req_.has_console()) {
        setsid();
        OpenConsole(req_.console());
    } else {
        ZapStdio();
    }

    SetProcessAttributes();

    std::vector<char*> expanded_args = ExpandArgsAndSetCmdline();

    __android_log_close();

    // Leaking file descriptors to the specialized process can cause security
    // issues or hard-to-debug bugs.  Before loading the target executable,
    // make sure only file descriptors requested by init are open.
    if (GetFileDescriptorCount() != req_.descriptors_size()) {
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

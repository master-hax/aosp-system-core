/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "snapuserd_transition.h"

#include <sys/socket.h>

#include <string>

#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <cutils/sockets.h>
#include <libsnapshot/snapshot.h>
#include <libsnapshot/snapuserd_client.h>
#include <private/android_filesystem_config.h>
#include <selinux/android.h>

#include "block_dev_initializer.h"
#include "service_utils.h"
#include "util.h"

namespace android {
namespace init {

using namespace std::string_literals;

using android::snapshot::SnapshotManager;
using android::snapshot::SnapuserdClient;

static constexpr char kSnapuserdPath[] = "/system/bin/snapuserd";
static constexpr char kSnapuserdFirstStagePidVar[] = "FIRST_STAGE_SNAPUSERD_PID";

void LaunchFirstStageSnapuserd(const std::string& secontext) {
    SocketDescriptor socket_desc;
    socket_desc.name = android::snapshot::kSnapuserdSocket;
    socket_desc.type = SOCK_STREAM;
    socket_desc.perm = 0660;
    socket_desc.uid = AID_SYSTEM;
    socket_desc.gid = AID_SYSTEM;

    auto socket = socket_desc.Create(secontext);
    if (!socket.ok()) {
        LOG(FATAL) << "Could not create snapuserd socket: " << socket.error();
    }

    pid_t pid = fork();
    if (pid < 0) {
        PLOG(FATAL) << "fork failed";
    }
    if (pid == 0) {
        socket->Publish();

        char arg0[] = "/system/bin/snapuserd";
        char* const argv[] = {arg0, nullptr};
        if (execv(arg0, argv) < 0) {
            PLOG(FATAL) << "execv failed";
        }
        _exit(127);
    }

    setenv(kSnapuserdFirstStagePidVar, std::to_string(pid).c_str(), 1);

    LOG(INFO) << "Relaunched snapuserd with pid: " << pid;
}

std::optional<pid_t> GetSnapuserdFirstStagePid() {
    const char* pid_str = getenv(kSnapuserdFirstStagePidVar);
    if (!pid_str) {
        return {};
    }

    int pid;
    if (!android::base::ParseInt(pid_str, &pid)) {
        LOG(ERROR) << "Could not parse pid in environment, " << kSnapuserdFirstStagePidVar << "="
                   << pid_str;
        return {};
    }
    return {pid};
}

static void RelaunchFirstStageSnapuserd() {
    selinux_android_restorecon("/dev/block", SELINUX_ANDROID_RESTORECON_RECURSE);
    selinux_android_restorecon("/dev/dm-user", SELINUX_ANDROID_RESTORECON_RECURSE);
    selinux_android_restorecon("/dev/socket", SELINUX_ANDROID_RESTORECON_RECURSE);
    selinux_android_restorecon("/metadata", SELINUX_ANDROID_RESTORECON_RECURSE);
    if (selinux_android_restorecon(kSnapuserdPath, SELINUX_ANDROID_RESTORECON_VERBOSE) == -1) {
        PLOG(FATAL) << "Could not restorecon SNAPUSERD";
    }

    std::string secontext;
    auto result = ComputeContextFromExecutable(kSnapuserdPath);
    if (!result.ok()) {
        LOG(FATAL) << "Could not compute context: " << result.error();
    }

    LaunchFirstStageSnapuserd(secontext);
}

void PerformSelinuxSnapuserdTransition() {
    if (IsRecoveryMode()) {
        return;
    }
    if (!SnapshotManager::IsSnapshotManagerNeeded()) {
        return;
    }

    auto sm = SnapshotManager::NewForFirstStageMount();
    if (!sm) {
        LOG(FATAL) << "Unable to create SnapshotManager";
        return;
    }
    if (!sm->NeedSnapshotsInFirstStageMount()) {
        return;
    }

    // Save the original pid before the re-launch overwrites it.
    auto orig_pid = GetSnapuserdFirstStagePid();
    if (!orig_pid) {
        LOG(FATAL) << "No pid found for first-stage snapuserd";
        return;
    }

    RelaunchFirstStageSnapuserd();

    // Only dm-user device names change during transitions, so the other
    // devices are expected to be present.
    BlockDevInitializer block_dev_init;
    sm->SetUeventRegenCallback([&block_dev_init](const std::string& device) -> bool {
        if (android::base::StartsWith(device, "/dev/dm-user/")) {
            return block_dev_init.InitDmUser(android::base::Basename(device));
        }
        return true;
    });

    if (!sm->PerformInitTransition(SnapshotManager::InitTransition::SELINUX)) {
        LOG(FATAL) << "Could not perform selinux transition";
    }

    // Socket is no longer needed, so remove it.
    CleanupSnapuserdSocket();

    KillFirstStageSnapuserd(orig_pid.value());
}

void KillFirstStageSnapuserd(pid_t pid) {
    if (kill(pid, SIGTERM) < 0 && errno != ESRCH) {
        LOG(ERROR) << "Kill snapuserd pid failed: " << pid;
    } else {
        LOG(INFO) << "Sent SIGTERM to snapuserd process " << pid;
    }
}

void CleanupSnapuserdSocket() {
    auto socket_path = ANDROID_SOCKET_DIR "/"s + android::snapshot::kSnapuserdSocket;
    if (access(socket_path.c_str(), F_OK) != 0) {
        return;
    }

    // Tell the daemon to stop accepting connections and to gracefully exit
    // once all outstanding handlers have terminated.
    if (auto client = SnapuserdClient::Connect(android::snapshot::kSnapuserdSocket, 3s)) {
        client->DetachSnapuserd();
    }

    // Unlink the socket so we can create it again in second-stage.
    if (unlink(socket_path.c_str()) < 0) {
        PLOG(ERROR) << "unlink " << socket_path << " failed";
    }
}

}  // namespace init
}  // namespace android

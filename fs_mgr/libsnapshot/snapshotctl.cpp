//
// Copyright (C) 2019 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <sysexits.h>

#include <chrono>
#include <iostream>
#include <map>
#include <sstream>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <libsnapshot/snapshot.h>
#include "utility.h"

#include "utility.h"

using namespace std::string_literals;

int Usage() {
    std::cerr << "snapshotctl: Control snapshots.\n"
                 "Usage: snapshotctl [action] [flags]\n"
                 "Actions:\n"
                 "  dump\n"
                 "    Print snapshot states.\n"
                 "  merge\n"
                 "    Initialize merge and wait for it to be completed.\n";
    return EX_USAGE;
}

namespace android {
namespace snapshot {

bool DumpCmdHandler(int /*argc*/, char** argv) {
    android::base::InitLogging(argv, &android::base::StderrLogger);
    return SnapshotManager::New()->Dump(std::cout);
}

bool MergeCmdHandler(int /*argc*/, char** argv) {
    auto begin = std::chrono::steady_clock::now();

    android::base::InitLogging(argv, android::base::StderrLogger);

    LOG(INFO) << "Initiating merge.";
    auto state = SnapshotManager::New()->InitiateMergeAndWait();

    // We could wind up in the Unverified state if the device rolled back or
    // hasn't fully rebooted. Ignore this.
    if (state == UpdateState::None || state == UpdateState::Unverified) {
        return true;
    }
    if (state == UpdateState::MergeCompleted) {
        auto end = std::chrono::steady_clock::now();
        auto passed = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
        LOG(INFO) << "Snapshot merged in " << passed << " ms.";
        return true;
    }

    LOG(ERROR) << "Snapshot failed to merge with state \"" << state
               << "\". You may want to remove update_engine states and retry the update.";
    return false;
}

static std::map<std::string, std::function<bool(int, char**)>> kCmdMap = {
        // clang-format off
        {"dump", DumpCmdHandler},
        {"merge", MergeCmdHandler},
        // clang-format on
};

}  // namespace snapshot
}  // namespace android

int main(int argc, char** argv) {
    using namespace android::snapshot;
    if (argc < 2) {
        return Usage();
    }

    for (const auto& cmd : kCmdMap) {
        if (cmd.first == argv[1]) {
            return cmd.second(argc, argv) ? EX_OK : EX_SOFTWARE;
        }
    }

    return Usage();
}

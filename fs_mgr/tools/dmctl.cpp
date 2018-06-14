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

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/dm-ioctl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include <dm.h>
#include <loop_control.h>

#include <algorithm>
#include <functional>
#include <iomanip>
#include <ios>
#include <iostream>
#include <map>
#include <string>
#include <vector>

using DeviceMapper = ::android::dm::DeviceMapper;
using DmTarget = ::android::dm::DmTarget;
using DmBlockDevice = ::android::dm::DeviceMapper::DmBlockDevice;
using DmTargetLinear = ::android::dm::DmTargetLinear;

static int Usage(void) {
    std::cerr << "usage: dmctl <command> [command options]" << std::endl;
    std::cerr << "commands:" << std::endl;
    std::cerr << "  create <dm-name> [[-ro] <dm-target> [-lo <filename>] <dm-target-args>]"
              << std::endl;
    std::cerr << "  delete <dm-name>" << std::endl;
    std::cerr << "  list <devices | targets>" << std::endl;
    std::cerr << "  help" << std::endl;
    std::cerr << "------" << std::endl;
    std::cerr << "For creating device with single dm-linear target:" << std::endl;
    std::cerr << "  1. To create identity mapped dm device with linear target that maps to /dev/foo"
                 "of size 1M"
              << std::endl;
    std::cerr << "    $ dmctl create FOO linear /dev/foo 0 2048 0" << std::endl;
    std::cerr << "  2. To create the exact same device but make it read-only." << std::endl;
    std::cerr << "    $ dmctl create FOO -ro linear /dev/foo 0 2048 0" << std::endl;
    std::cerr << "  4. To create the exact same device but make it read-only AND map it to a file "
                 "(foo.img) using a loopback device"
              << std::endl;
    std::cerr << "    $ dmctl create FOO -ro linear -lo foo.img 0 2048 0" << std::endl;
    return -EINVAL;
}

static std::string AttachLoopbackDevice(std::string& file) {
    UNUSED(file);
    return std::string();
}

static int DmCreateTargetLinear(int argc, std::vector<std::string>& args,
                                std::vector<DmTarget>* targets) {
    // check for minimum number of arguments required to create a Linear target
    if (argc < 4) {
        std::cerr << "Need atleast 4 arguments to create 'linear' target" << std::endl;
        return -EINVAL;
    }
    int consumed = 0;

    // path of the target device for linear;
    std::string dev;
    consumed++;
    if (args[0] == "-lo") {
        args.erase(args.begin());
        LoopControl lc;
        if (!lc.attach(args[0], &dev)) {
            LOG(ERROR) << "Failed to get a loopback device for: " << args[0];
            return -errno;
        }
        consumed++;
        args.erase(args.begin());
        std::cout << "Using loopback device: " << dev << std::endl;
    } else {
        dev = *(args.erase(args.begin()));
    }

    uint64_t offset = strtoull(args[0].c_str(), NULL, 10);
    uint64_t length = strtoull(args[1].c_str(), NULL, 10);
    uint64_t dm_start = strtoull(args[2].c_str(), NULL, 10);
    args.erase(args.begin(), args.begin() + 2);
    consumed += 3;

    targets->emplace_back(DmTargetLinear(offset, length, dm_start, dev));
    return consumed;
}

// All handlers in the targetmap return the number of arguments consumed
// from argv[]
// clang-format off
static std::map<std::string, std::function<int(int, std::vector<std::string>&, std::vector<DmTarget>*)>>
    targetmap = {
        {"linear", DmCreateTargetLinear},
};
// clang-format on

static int DmCreateCmdHandler(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "'name' MUST be provided for target device";
        return -EINVAL;
    }

    // start tracking the arguments as we consume them
    std::vector<std::string> args(argv, argv + argc);

    // TODO(b/110035986): This currently doesn't cleanup
    // the created devices if something goes wrong along
    // the way for configuring a device. This allows us to unit
    // test create() and delete(). All other clients of
    // libdm however, should not override the default
    // parameter for the DeviceMapper::Instance()
    DeviceMapper& dm = DeviceMapper::Instance(false);

    // first argument is always the name of the device
    if (!dm.CreateDevice(args[0])) {
        std::cerr << "Failed to create: " << args[0] << std::endl;
        return -EIO;
    }

    --argc;
    args.erase(args.begin());

    // if we also have target specified
    bool is_readonly = false, parse_targets = false;
    // targets to be added to the table
    std::vector<DmTarget> targets;

    while (argc > 0) {
        if (!parse_targets && ::android::base::StartsWith(args[0], "-")) {
            if (args[0] != "-ro") {
                std::cerr << "Invalid arguments" << std::endl;
                // FIXME: For DEBUG only
                std::cerr << "argc: " << argc << " arg:" << args[0] << std::endl;
                std::cerr << "remaining arguments: " << ::android::base::Join(args, ',')
                          << std::endl;
                std::cerr << "See: dmctl help" << std::endl;
                return -EINVAL;
            }
            is_readonly = true;
            parse_targets = true;
            --argc;
            args.erase(args.begin());
            if (argc == 0) {
                LOG(ERROR) << "Insufficient arguments: at least one target must be specified";
                return -EINVAL;
            }
        }

        for (const auto& t : targetmap) {
            int consumed = 0;
            if (t.first == args[0]) {
                --argc;
                args.erase(args.begin());
                consumed = t.second(argc, args, &targets);
                if (consumed <= 0) {
                    LOG(ERROR) << "Invalid arguments for [" << t.first
                               << "] target: " << ::android::base::Join(args, ',');
                    return -EINVAL;
                }
                argc -= consumed;
                args.erase(args.begin(), args.begin() + consumed);
                CHECK(argc >= 0) << "Invalid argument parsing, argc turned negative";
            } else {
                LOG(ERROR) << "Unsupported Target: " << args[0];
                LOG(ERROR) << " args:" << ::android::base::Join(args, ",");
                return -EINVAL;
            }
        }
    }

    // For DEBUG only
    LOG(INFO) << "Created Device: " << argv[0];
    LOG(INFO) << "  is_readonly: " << is_readonly;
    LOG(INFO) << "  target_count: " << targets.size();
    return 0;
}

static int DmDeleteCmdHandler(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Atleast 'name' MUST be provided for target device";
        return -EINVAL;
    }

    std::string name = argv[0];
    DeviceMapper& dm = DeviceMapper::Instance();
    if (!dm.DeleteDevice(name)) {
        std::cerr << "Failed to delete [" << name << "]" << std::endl;
        return -EIO;
    }

    return 0;
}

static int DmListTargets(DeviceMapper& dm) {
    std::vector<DmTarget> targets;
    if (!dm.GetAvailableTargets(&targets)) {
        std::cerr << "Failed to read available device mapper targets" << std::endl;
        return -errno;
    }

    std::cout << "Available Device Mapper Targets:" << std::endl;
    if (targets.empty()) {
        std::cout << "  <empty>" << std::endl;
        return 0;
    }

    for (const auto& target : targets) {
        std::cout << std::left << std::setw(20) << target.name() << " : " << target.version()
                  << std::endl;
    }

    return 0;
}

static int DmListDevices(DeviceMapper& dm) {
    std::vector<DmBlockDevice> devices;
    if (!dm.GetAvailableDevices(&devices)) {
        std::cerr << "Failed to read available device mapper devices" << std::endl;
        return -errno;
    }
    std::cout << "Available Device Mapper Devices:" << std::endl;
    if (devices.empty()) {
        std::cout << "  <empty>" << std::endl;
        return 0;
    }

    for (const auto& dev : devices) {
        std::cout << std::left << std::setw(20) << dev.name() << " : " << dev.Major() << ":"
                  << dev.Minor() << std::endl;
    }

    return 0;
}

static const std::map<std::string, std::function<int(DeviceMapper&)>> listmap = {
        {"targets", DmListTargets},
        {"devices", DmListDevices},
};

static int DmListCmdHandler(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Invalid arguments, see \'dmctl help\'" << std::endl;
        return -EINVAL;
    }

    DeviceMapper& dm = DeviceMapper::Instance();
    for (const auto& l : listmap) {
        if (l.first == argv[0]) return l.second(dm);
    }

    std::cerr << "Invalid argument to \'dmctl list\': " << argv[0] << std::endl;
    return -EINVAL;
}

static int HelpCmdHandler(int /* argc */, char** /* argv */) {
    Usage();
    return 0;
}

static std::map<std::string, std::function<int(int, char**)>> cmdmap = {
        {"create", DmCreateCmdHandler},
        {"delete", DmDeleteCmdHandler},
        {"list", DmListCmdHandler},
        {"help", HelpCmdHandler},
};

int main(int argc, char** argv) {
    android::base::InitLogging(argv, &android::base::StderrLogger);
    if (argc < 2) {
        return Usage();
    }

    for (const auto& cmd : cmdmap) {
        if (cmd.first == argv[1]) {
            return cmd.second(argc - 2, argv + 2);
        }
    }

    return Usage();
}

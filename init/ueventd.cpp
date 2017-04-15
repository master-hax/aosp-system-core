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

#include "ueventd.h"

#include <ctype.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <selinux/selinux.h>

#include "devices.h"
#include "log.h"
#include "util.h"

template <bool sysfs>
static bool ParseSingleLine(std::vector<std::string>&& line, std::string* err);

int ueventd_main(int argc, char **argv)
{
    /*
     * init sets the umask to 077 for forked processes. We need to
     * create files with exact permissions, without modification by
     * the umask.
     */
    umask(000);

    /* Prevent fire-and-forget children from becoming zombies.
     * If we should need to wait() for some children in the future
     * (as opposed to none right now), double-forking here instead
     * of ignoring SIGCHLD may be the better solution.
     */
    signal(SIGCHLD, SIG_IGN);

    InitKernelLogging(argv);

    LOG(INFO) << "ueventd started!";

    selinux_callback cb;
    cb.func_log = selinux_klog_callback;
    selinux_set_callback(SELINUX_CB_LOG, cb);

    Parser& parser = Parser::GetInstance();
    parser.AddSectionParser("service", std::make_unique<SubsystemParser>());
    parser.AddSingleLineParser("/sys/", &ParseSingleLine<true>);
    parser.AddSingleLineParser("/dev/", &ParseSingleLine<false>);
    parser.ParseConfig("/ueventd.rc");
    parser.ParseConfig("/vendor/ueventd.rc");
    parser.ParseConfig("/odm/ueventd.rc");

    /*
     * keep the current product name base configuration so
     * we remain backwards compatible and allow it to override
     * everything
     * TODO: cleanup platform ueventd.rc to remove vendor specific
     * device node entries (b/34968103)
     */
    std::string hardware = android::base::GetProperty("ro.hardware", "");
    parser.ParseConfig("/ueventd." + hardware + ".rc");

    device_init();

    pollfd ufd;
    ufd.events = POLLIN;
    ufd.fd = get_device_fd();

    while (true) {
        ufd.revents = 0;
        int nr = poll(&ufd, 1, -1);
        if (nr <= 0) {
            continue;
        }
        if (ufd.revents & POLLIN) {
            handle_device_fd();
        }
    }

    return 0;
}

std::vector<Subsystem> subsystems;

bool SubsystemParser::ParseSection(const std::vector<std::string>& args, std::string* err) {
    if (std::find(subsystems.begin(), subsystems.end(), args[1]) != subsystems.end()) {
        *err = "ignoring duplicate subsystem entry";
        return false;
    }

    subsystem_.name = args[1];

    return true;
}

bool SubsystemParser::ParseLineSection(const std::vector<std::string>& args,
                                       const std::string& filename, int line, std::string* err) {
    if (args[0] == "devname") {
        if (args[1] == "uevent_devname") {
            subsystem_.devname_source = Subsystem::DevnameSource::DEVNAME_UEVENT_DEVNAME;
        } else if (args[1] == "uevent_devpath") {
            subsystem_.devname_source = Subsystem::DevnameSource::DEVNAME_UEVENT_DEVPATH;
        } else {
            *err = "invalid devname '" + args[1] + "'";
            return false;
        }
    } else if (args[0] == "dirname") {
        if (args[1].front() != '/') {
            *err = "dirname '" + args[1] + " ' does not start with '/'";
            return false;
        }
        subsystem_.dir_name = args[1];
    }
    return true;
}

void SubsystemParser::EndSection() {
    subsystems.emplace_back(std::move(subsystem_));
}

template <bool sysfs>
static bool ParseSingleLine(std::vector<std::string>&& args, std::string* err) {
    std::string sysfs_attribute;
    if (sysfs) {
        if (args.size() != 5) {
            *err = "/sys/ lines must have 5 entries";
            return false;
        }
        // Capture the 'attribute' for sysfs then remove it, such that the rest can be parsed in
        // common with the dev permissions.
        sysfs_attribute = args[1];
        args.erase(args.begin() + 1);
    }

    if (!sysfs && args.size() != 4) {
        *err = "/dev/ lines must have 4 entries";
        return false;
    }

    // args is now <name> <perm> <uid> <gid>
    const std::string& name = args[0];

    std::size_t end_pointer = 0;
    mode_t perm = std::stoul(args[1], &end_pointer, 8);
    if (end_pointer == 0 || args[1][end_pointer] != '\0') {
        *err = "invalid mode '" + args[1] + "'";
        return false;
    }

    passwd* pwd = getpwnam(args[2].c_str());
    if (!pwd) {
        *err = "invalid uid '" + args[2] + "'";
        return false;
    }
    uid_t uid = pwd->pw_uid;

    struct group* grp = getgrnam(args[3].c_str());
    if (!grp) {
        *err = "invalid gid '" + args[3] + "'";
        return false;
    }
    gid_t gid = grp->gr_gid;

    if (sysfs) {
        sysfs_permissions.emplace_back(name, sysfs_attribute, perm, uid, gid);
    } else {
        dev_permissions.emplace_back(name, perm, uid, gid);
    }
    return true;
}

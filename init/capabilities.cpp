// Copyright (C) 2016 The Android Open Source Project
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

#include "capabilities.h"

#include <sys/capability.h>
#include <sys/prctl.h>

#include <map>
#include <memory>

#include <android-base/logging.h>

#define CAP_MAP_ENTRY(cap) { #cap, CAP_ ## cap }

namespace {
const std::map<std::string, int> cap_map = {
    CAP_MAP_ENTRY(CHOWN),
    CAP_MAP_ENTRY(DAC_OVERRIDE),
    CAP_MAP_ENTRY(DAC_READ_SEARCH),
    CAP_MAP_ENTRY(FOWNER),
    CAP_MAP_ENTRY(FSETID),
    CAP_MAP_ENTRY(KILL),
    CAP_MAP_ENTRY(SETGID),
    CAP_MAP_ENTRY(SETUID),
    CAP_MAP_ENTRY(SETPCAP),
    CAP_MAP_ENTRY(LINUX_IMMUTABLE),
    CAP_MAP_ENTRY(NET_BIND_SERVICE),
    CAP_MAP_ENTRY(NET_BROADCAST),
    CAP_MAP_ENTRY(NET_ADMIN),
    CAP_MAP_ENTRY(NET_RAW),
    CAP_MAP_ENTRY(IPC_LOCK),
    CAP_MAP_ENTRY(IPC_OWNER),
    CAP_MAP_ENTRY(SYS_MODULE),
    CAP_MAP_ENTRY(SYS_RAWIO),
    CAP_MAP_ENTRY(SYS_CHROOT),
    CAP_MAP_ENTRY(SYS_PTRACE),
    CAP_MAP_ENTRY(SYS_PACCT),
    CAP_MAP_ENTRY(SYS_ADMIN),
    CAP_MAP_ENTRY(SYS_BOOT),
    CAP_MAP_ENTRY(SYS_NICE),
    CAP_MAP_ENTRY(SYS_RESOURCE),
    CAP_MAP_ENTRY(SYS_TIME),
    CAP_MAP_ENTRY(SYS_TTY_CONFIG),
    CAP_MAP_ENTRY(MKNOD),
    CAP_MAP_ENTRY(LEASE),
    CAP_MAP_ENTRY(AUDIT_WRITE),
    CAP_MAP_ENTRY(AUDIT_CONTROL),
    CAP_MAP_ENTRY(SETFCAP),
    CAP_MAP_ENTRY(MAC_OVERRIDE),
    CAP_MAP_ENTRY(MAC_ADMIN),
    CAP_MAP_ENTRY(SYSLOG),
    CAP_MAP_ENTRY(WAKE_ALARM),
    CAP_MAP_ENTRY(BLOCK_SUSPEND),
    CAP_MAP_ENTRY(AUDIT_READ),
};

static_assert(CAP_LAST_CAP == CAP_AUDIT_READ, "CAP_LAST_CAP is not CAP_AUDIT_READ");

bool drop_bounding_set(const CapSet& to_keep) {
    for (unsigned int cap = 0; cap < to_keep.size(); ++cap) {
        if (to_keep.test(cap)) {
            // No need to drop this capability.
            continue;
        }
        if (cap_drop_bound(cap) == -1) {
            PLOG(ERROR) << "cap_drop_bound(" << cap << ") failed";
            return false;
        }
    }
    return true;
}

bool set_inh_prm_eff_caps(const CapSet& to_keep) {
    cap_t caps = cap_init();
    auto deleter = [](cap_t* p) { cap_free(*p); };
    std::unique_ptr<cap_t, decltype(deleter)> ptr_caps(&caps, deleter);

    cap_clear(caps);
    cap_value_t cap_value[1];
    for (unsigned int cap = 0; cap <= to_keep.size(); ++cap) {
        if (to_keep.test(cap)) {
            cap_value[0] = cap;
            if (cap_set_flag(caps, CAP_INHERITABLE, sizeof(cap_value), cap_value, CAP_SET) != 0 ||
                cap_set_flag(caps, CAP_PERMITTED, sizeof(cap_value), cap_value, CAP_SET) != 0 ||
                cap_set_flag(caps, CAP_EFFECTIVE, sizeof(cap_value), cap_value, CAP_SET) != 0) {
                LOG(ERROR) << "cap_set_flag(" << cap << ") failed";
                return false;
            }
        }
    }

    if (cap_set_proc(caps) != 0) {
        PLOG(ERROR) << "cap_set_proc(" << to_keep.to_ulong() << ") failed";
        return false;
    }
    return true;
}

bool set_ambient_caps(const CapSet& to_raise) {
    for (unsigned int cap = 0; cap < to_raise.size(); ++cap) {
        if (to_raise.test(cap)) {
            if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) != 0) {
                PLOG(ERROR) << "prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, " << cap << ") failed";
                return false;
            }
        }
    }
    return true;
}

}  // namespace anonymous

int lookup_cap(const std::string& cap_name) {
    auto e = cap_map.find(cap_name);
    if (e != cap_map.end()) {
        return e->second;
    } else {
        return -1;
    }
}

bool set_caps(const CapSet& to_keep) {
    CapSet caps = to_keep;

    // Need to keep SETPCAP to drop bounding set below.
    caps.set(CAP_SETPCAP);
    if (!set_inh_prm_eff_caps(caps)) {
        LOG(ERROR) << "failed to apply initial capset";
        return false;
    }

    if (!drop_bounding_set(to_keep)) {
        return false;
    }

    // If SETPCAP wasn't specifically requested, drop it now.
    if (!to_keep.test(CAP_SETPCAP)) {
        caps.reset(CAP_SETPCAP);
        if (!set_inh_prm_eff_caps(caps)) {
            LOG(ERROR) << "failed to apply final capset";
            return false;
        }
    }

    // Add the capabilities to the ambient set so that they are preserved across
    // execve(2).
    // See http://man7.org/linux/man-pages/man7/capabilities.7.html.
    return set_ambient_caps(to_keep);
}

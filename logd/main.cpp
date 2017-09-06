/*
 * Copyright (C) 2012-2013 The Android Open Source Project
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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/klog.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <memory>
#include <thread>

#include <android-base/macros.h>
#include <android-base/properties.h>
#include <cutils/android_get_control_file.h>
#include <cutils/properties.h>
#include <cutils/sched_policy.h>
#include <cutils/sockets.h>
#include <log/event_tag_map.h>
#include <private/android_filesystem_config.h>
#include <private/android_logger.h>
#include <utils/threads.h>

#include "CommandListener.h"
#include "LogAudit.h"
#include "LogBuffer.h"
#include "LogKlog.h"
#include "LogListener.h"
#include "LogUtils.h"

#define KMSG_PRIORITY(PRI)                                 \
    '<', '0' + LOG_MAKEPRI(LOG_DAEMON, LOG_PRI(PRI)) / 10, \
        '0' + LOG_MAKEPRI(LOG_DAEMON, LOG_PRI(PRI)) % 10, '>'

//
// The service is designed to be run by init, it does not respond well
// to starting up manually. When starting up manually the sockets will
// fail to open typically for one of the following reasons:
//     EADDRINUSE if logger is running.
//     EACCESS if started without precautions (below)
//
// Here is a cookbook procedure for starting up logd manually assuming
// init is out of the way, pedantically all permissions and SELinux
// security is put back in place:
//
//    setenforce 0
//    rm /dev/socket/logd*
//    chmod 777 /dev/socket
//        # here is where you would attach the debugger or valgrind for example
//    runcon u:r:logd:s0 /system/bin/logd </dev/null >/dev/null 2>&1 &
//    sleep 1
//    chmod 755 /dev/socket
//    chown logd.logd /dev/socket/logd*
//    restorecon /dev/socket/logd*
//    setenforce 1
//
// If minimalism prevails, typical for debugging and security is not a concern:
//
//    setenforce 0
//    chmod 777 /dev/socket
//    logd
//

static int drop_privs(bool klogd, bool auditd) {
    // Tricky, if ro.build.type is "eng" then this is true because of the
    // side effect that ro.debuggable == 1 as well, else it is false.
    bool eng =
        __android_logger_property_get_bool("ro.build.type", BOOL_DEFAULT_FALSE);

    struct sched_param param;
    memset(&param, 0, sizeof(param));

    if (set_sched_policy(0, SP_BACKGROUND) < 0) {
        android::prdebug("failed to set background scheduling policy");
        if (!eng) return -1;
    }

    if (sched_setscheduler((pid_t)0, SCHED_BATCH, &param) < 0) {
        android::prdebug("failed to set batch scheduler");
        if (!eng) return -1;
    }

    if (setpriority(PRIO_PROCESS, 0, ANDROID_PRIORITY_BACKGROUND) < 0) {
        android::prdebug("failed to set background cgroup");
        if (!eng) return -1;
    }

    if (!eng && (prctl(PR_SET_DUMPABLE, 0) < 0)) {
        android::prdebug("failed to clear PR_SET_DUMPABLE");
        return -1;
    }

    if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
        android::prdebug("failed to set PR_SET_KEEPCAPS");
        if (!eng) return -1;
    }

    std::unique_ptr<struct _cap_struct, int (*)(void*)> caps(cap_init(),
                                                             cap_free);
    if (cap_clear(caps.get()) < 0) return -1;
    cap_value_t cap_value[] = { CAP_SETGID,  // must be first for below
                                klogd ? CAP_SYSLOG : CAP_SETGID,
                                auditd ? CAP_AUDIT_CONTROL : CAP_SETGID };
    if (cap_set_flag(caps.get(), CAP_PERMITTED, arraysize(cap_value), cap_value,
                     CAP_SET) < 0) {
        return -1;
    }
    if (cap_set_flag(caps.get(), CAP_EFFECTIVE, arraysize(cap_value), cap_value,
                     CAP_SET) < 0) {
        return -1;
    }
    if (cap_set_proc(caps.get()) < 0) {
        android::prdebug(
            "failed to set CAP_SETGID, CAP_SYSLOG or CAP_AUDIT_CONTROL (%d)",
            errno);
        if (!eng) return -1;
    }

    gid_t groups[] = {
        AID_READPROC,
        AID_SYSTEM,        // search access to /data/system path
        AID_PACKAGE_INFO,  // readonly access to /data/system/packages.list
    };

    if (setgroups(arraysize(groups), groups) == -1) {
        android::prdebug("failed to set AID_READPROC groups");
        if (!eng) return -1;
    }

    if (setgid(AID_LOGD) != 0) {
        android::prdebug("failed to set AID_LOGD gid");
        if (!eng) return -1;
    }

    if (setuid(AID_LOGD) != 0) {
        android::prdebug("failed to set AID_LOGD uid");
        if (!eng) return -1;
    }

    if (cap_set_flag(caps.get(), CAP_PERMITTED, 1, cap_value, CAP_CLEAR) < 0) {
        return -1;
    }
    if (cap_set_flag(caps.get(), CAP_EFFECTIVE, 1, cap_value, CAP_CLEAR) < 0) {
        return -1;
    }
    if (cap_set_proc(caps.get()) < 0) {
        android::prdebug("failed to clear CAP_SETGID (%d)", errno);
        if (!eng) return -1;
    }

    return 0;
}

// Property helper
static bool check_flag(const char* prop, const char* flag) {
    const char* cp = strcasestr(prop, flag);
    if (!cp) {
        return false;
    }
    // We only will document comma (,)
    static const char sep[] = ",:;|+ \t\f";
    if ((cp != prop) && !strchr(sep, cp[-1])) {
        return false;
    }
    cp += strlen(flag);
    return !*cp || !!strchr(sep, *cp);
}

static int fdDmesg = -1;
void android::prdebug(const char* fmt, ...) {
    if (fdDmesg < 0) {
        return;
    }

    static const char message[] = {
        KMSG_PRIORITY(LOG_DEBUG), 'l', 'o', 'g', 'd', ':', ' '
    };
    char buffer[256];
    memcpy(buffer, message, sizeof(message));

    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buffer + sizeof(message),
                      sizeof(buffer) - sizeof(message), fmt, ap);
    va_end(ap);
    if (n > 0) {
        buffer[sizeof(buffer) - 1] = '\0';
        if (!strchr(buffer, '\n')) {
            buffer[sizeof(buffer) - 2] = '\0';
            strlcat(buffer, "\n", sizeof(buffer));
        }
        write(fdDmesg, buffer, strlen(buffer));
    }
}

// ReinitThread reinitializes logBuf in two cases:
// 1) Once ro.persistent_properties.ready=true, which indicates persistent
//    properties such as persist.logd.size are ready to be read, as well as
//    other files on data.
// 2) On subsequent changes to persist.logd.size, which is set by the settings
//    app.
static void ReinitThread(LogBuffer* logBuf) {
    prctl(PR_SET_NAME, "logd.daemon");
    android::base::WaitForProperty("ro.persistent_properties.ready", "true");

    auto persist_logd_size_property =
        __system_property_find("persist.logd.size");
    uint32_t persist_logd_size_serial = 0;

    if (persist_logd_size_property != nullptr) {
        __system_property_read_callback(
            persist_logd_size_property,
            [](void* cookie, const char*, const char*, uint32_t serial) {
                auto result =
                    reinterpret_cast<decltype(persist_logd_size_serial)*>(
                        cookie);
                *result = serial;
            },
            &persist_logd_size_serial);
    }

    while (true) {
        if (fdDmesg >= 0) {
            std::string reinit_message = { KMSG_PRIORITY(LOG_INFO) };
            reinit_message += "logd.daemon: reinit\n";
            write(fdDmesg, reinit_message.c_str(), reinit_message.size());
        }
        // Anything that reads persist.<property>
        logBuf->init();
        logBuf->initPrune(nullptr);

        uint32_t global_serial = 0;
        while (persist_logd_size_property == nullptr) {
            __system_property_wait(nullptr, global_serial, &global_serial,
                                   nullptr);
            persist_logd_size_property =
                __system_property_find("persist.logd.size");
        }
        __system_property_wait(persist_logd_size_property,
                               persist_logd_size_serial,
                               &persist_logd_size_serial, nullptr);
    }
}

static void readDmesg(LogAudit* al, LogKlog* kl) {
    if (!al && !kl) {
        return;
    }

    int rc = klogctl(KLOG_SIZE_BUFFER, nullptr, 0);
    if (rc <= 0) {
        return;
    }

    // Margin for additional input race or trailing nul
    ssize_t len = rc + 1024;
    std::unique_ptr<char[]> buf(new char[len]);

    rc = klogctl(KLOG_READ_ALL, buf.get(), len);
    if (rc <= 0) {
        return;
    }

    if (rc < len) {
        len = rc + 1;
    }
    buf[--len] = '\0';

    if (kl && kl->isMonotonic()) {
        kl->synchronize(buf.get(), len);
    }

    ssize_t sublen;
    for (char *ptr = nullptr, *tok = buf.get();
         (rc >= 0) && !!(tok = android::log_strntok_r(tok, len, ptr, sublen));
         tok = nullptr) {
        if ((sublen <= 0) || !*tok) continue;
        if (al) {
            rc = al->log(tok, sublen);
        }
        if (kl) {
            rc = kl->log(tok, sublen);
        }
    }
}

// Foreground waits for exit of the main persistent threads
// that are started here. The threads are created to manage
// UNIX domain client sockets for writing, reading and
// controlling the user space logger, and for any additional
// logging plugins like auditd and restart control. Additional
// transitory per-client threads are created for each reader.
int main() {
    // logd is written under the assumption that the timezone is UTC.
    // If TZ is not set, persist.sys.timezone is looked up in some time utility
    // libc functions, including mktime. It confuses the logd time handling,
    // so here explicitly set TZ to UTC, which overrides the property.
    setenv("TZ", "UTC", 1);

    static const char dev_kmsg[] = "/dev/kmsg";
    fdDmesg = android_get_control_file(dev_kmsg);
    if (fdDmesg < 0) {
        fdDmesg = TEMP_FAILURE_RETRY(open(dev_kmsg, O_WRONLY | O_CLOEXEC));
    }

    int fdPmesg = -1;
    bool klogd = __android_logger_property_get_bool(
        "logd.kernel", BOOL_DEFAULT_TRUE | BOOL_DEFAULT_FLAG_PERSIST |
                           BOOL_DEFAULT_FLAG_ENG | BOOL_DEFAULT_FLAG_SVELTE);
    if (klogd) {
        static const char proc_kmsg[] = "/proc/kmsg";
        fdPmesg = android_get_control_file(proc_kmsg);
        if (fdPmesg < 0) {
            fdPmesg = TEMP_FAILURE_RETRY(
                open(proc_kmsg, O_RDONLY | O_NDELAY | O_CLOEXEC));
        }
        if (fdPmesg < 0) android::prdebug("Failed to open %s\n", proc_kmsg);
    }

    bool auditd =
        __android_logger_property_get_bool("ro.logd.auditd", BOOL_DEFAULT_TRUE);
    if (drop_privs(klogd, auditd) != 0) {
        return -1;
    }

    // Serves the purpose of managing the last logs times read on a
    // socket connection, and as a reader lock on a range of log
    // entries.

    LastLogTimes* times = new LastLogTimes();

    // LogBuffer is the object which is responsible for holding all
    // log entries.

    LogBuffer* logBuf = new LogBuffer(times);

    auto reinit_thread = std::thread([logBuf]() { ReinitThread(logBuf); });
    reinit_thread.detach();

    if (__android_logger_property_get_bool(
            "logd.statistics", BOOL_DEFAULT_TRUE | BOOL_DEFAULT_FLAG_PERSIST |
                                   BOOL_DEFAULT_FLAG_ENG |
                                   BOOL_DEFAULT_FLAG_SVELTE)) {
        logBuf->enableStatistics();
    }

    // LogReader listens on /dev/socket/logdr. When a client
    // connects, log entries in the LogBuffer are written to the client.

    LogReader* reader = new LogReader(logBuf);
    if (reader->startListener()) {
        exit(1);
    }

    // LogListener listens on /dev/socket/logdw for client
    // initiated log messages. New log entries are added to LogBuffer
    // and LogReader is notified to send updates to connected clients.

    LogListener* swl = new LogListener(logBuf, reader);
    // Backlog and /proc/sys/net/unix/max_dgram_qlen set to large value
    if (swl->startListener(600)) {
        exit(1);
    }

    // Command listener listens on /dev/socket/logd for incoming logd
    // administrative commands.

    CommandListener* cl = new CommandListener(logBuf, reader, swl);
    if (cl->startListener()) {
        exit(1);
    }

    // LogAudit listens on NETLINK_AUDIT socket for selinux
    // initiated log messages. New log entries are added to LogBuffer
    // and LogReader is notified to send updates to connected clients.

    LogAudit* al = nullptr;
    if (auditd) {
        al = new LogAudit(logBuf, reader,
                          __android_logger_property_get_bool(
                              "ro.logd.auditd.dmesg", BOOL_DEFAULT_TRUE)
                              ? fdDmesg
                              : -1);
    }

    LogKlog* kl = nullptr;
    if (klogd) {
        kl = new LogKlog(logBuf, reader, fdDmesg, fdPmesg, al != nullptr);
    }

    readDmesg(al, kl);

    // failure is an option ... messages are in dmesg (required by standard)

    if (kl && kl->startListener()) {
        delete kl;
    }

    if (al && al->startListener()) {
        delete al;
    }

    TEMP_FAILURE_RETRY(pause());

    exit(0);
}

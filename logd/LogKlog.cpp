/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <syslog.h>

#include "LogKlog.h"

#define KMSG_PRIORITY(PRI)           \
    '<',                             \
    '0' + (LOG_SYSLOG | (PRI)) / 10, \
    '0' + (LOG_SYSLOG | (PRI)) % 10, \
    '>'

LogKlog::LogKlog(LogBuffer *buf, LogReader *reader, int fdWrite, int fdRead, bool auditd)
        : SocketListener(fdRead, false)
        , logbuf(buf)
        , reader(reader)
        , fdWrite(fdWrite)
        , fdRead(fdRead)
        , signature(CLOCK_MONOTONIC)
        , initialized(false)
        , prefix(false)
        , suffix(false)
        , auditd(auditd) {
    static const char priority_message[] = { KMSG_PRIORITY(LOG_INFO) };
    static const char klogd_message[] = "%slogd.klogd: %" PRIu64 "\n";
    char buffer[sizeof(priority_message) + sizeof(klogd_message) + 20 - 4];
    snprintf(buffer, sizeof(buffer), klogd_message, priority_message,
        signature.nsec());
    write(fdWrite, buffer, strlen(buffer));
}

bool LogKlog::onDataAvailable(SocketClient *cli) {
    if (!initialized) {
        prctl(PR_SET_NAME, "logd.klogd");
        initialized = true;
    }

    char buffer[4096];
    size_t len = 0;

    for(;;) {
        ssize_t retval = 0;
        if ((sizeof(buffer) - 1 - len) > 0) {
            retval = read(cli->getSocket(), buffer + len, sizeof(buffer) - 1 - len);
        }
        if ((retval == 0) && (len == 0)) {
            break;
        }
        if (retval < 0) {
            return false;
        }
        len += retval;
        bool full = len == (sizeof(buffer) - 1);
        char *ep = buffer + len;
        *ep = '\0';
        len = 0;
        for(char *ptr, *tok = buffer;
                ((tok = strtok_r(tok, "\r\n", &ptr)));
                tok = NULL) {
            if (((tok + strlen(tok)) == ep) && (retval != 0) && full) {
                len = strlen(tok);
                memmove(buffer, tok, len);
                break;
            }
            if (*tok) {
                log(tok);
            }
        }
    }

    return true;
}

// Filter heuristics:
// LOG_KERN (0):
// <PRI>[<TIME>] <tag> : message
// <PRI>[<TIME>] <tag> <tag> : message
// <PRI>[<TIME>] <tag> <tag>_work : message
// <PRI>[<TIME>] <tag> '<tag>.<num>' : message
// <PRI>[<TIME>] <tag> '<tag><num>' : message
// <PRI>[<TIME>] <tag>_host '<tag>.<num>' : message
// (unimplemented) <PRI>[<TIME>] <tag> '<num>.<tag>' : message
// <PRI>[<TIME>] [INFO]<tag> : message
// <PRI>[<TIME>] ------------[ cut here ]------------   (?)
// <PRI>[<TIME>] ---[ end trace 3225a3070ca3e4ac ]---   (?)
// LOG_USER, LOG_MAIL, LOG_DAEMON, LOG_AUTH, LOG_SYSLOG, LOG_LPR, LOG_NEWS
// LOG_UUCP, LOG_CRON, LOG_AUTHPRIV, LOG_FTP:
// <PRI+TAG>[<TIME>] (see sys/syslog.h)
// Observe:
//  Minimum tag length = 3   NB: drops things like r5:c00bbadf
//  Maximum tag words = 2
//  Maximum tag length = 16  NB: we are thinking of how ugly logcat can get.
//  Not a Tag if there is no message content.
//  leading additional spaces means no tag, inherit last tag.
//  Not a Tag if ERROR: WARNING: INFO: CPU:
// Drop:
//  empty messages
//  messages with ' audit(' in them
//  messages with 'logd.auditd:'
//  messages with 'logd.klogd:'
// return -1 if message logd.klogd: <signature>
int LogKlog::log(const char *buf) {
    static const char audit_str[] = " audit(";
    const char *cp = strstr(buf, audit_str);
    if (cp && auditd) {
        return 0;
    }

    int pri = LOG_USER | LOG_INFO;
    cp = buf;
    if (*buf == '<') {
        pri = 0;
        while(isdigit(*++buf)) {
            pri = (pri * 10) + *buf - '0';
        }
        if (*buf == '>') {
            ++buf;
        } else {
            buf = cp;
            pri = LOG_USER | LOG_INFO;
        }
    }

    log_time mono, real;
    if ((cp = mono.strptime(buf, "[ %s.%q]"))) {
        real = mono;
        logbuf->convertIfMonotonicToReal(real);
        if (isspace(*cp)) {
            ++cp;
        }
        buf = cp;
    } else {
        mono = log_time(CLOCK_MONOTONIC);
        real = log_time(CLOCK_REALTIME);
    }

    const char auditd_message[] = "logd.auditd: ";
    if (!strncmp(buf, auditd_message, sizeof(auditd_message) - 1)) {
        return 0;
    }
    const char klogd_message[] = "logd.klogd: ";
    if (!strncmp(buf, klogd_message, sizeof(klogd_message) - 1)) {
        uint64_t sig = atol(buf + sizeof(klogd_message) - 1);
        if (sig == signature.nsec()) {
            if (initialized) {
                suffix = true;
            } else {
                prefix = true;
            }
            return -1;
        }
        return 0;
    }

    if (initialized ? !suffix : prefix) {
        return 0;
    }

    pid_t pid = 0;
    pid_t tid = 0;
    uid_t uid = 0;

    // Heuristics to pull out a tag from the message
    const char *start = buf;
    const char *tag = "";
    const char *etag = tag;
    if (!isspace(*buf)) {
        const char *bt;
        const char *et;

        bt = buf;
        if (!strncmp(buf, "[INFO]", 6)) {
            // <PRI>[<TIME>] [INFO]<tag> : message
            bt = buf + 6;
        }
        for(et = bt; *et && (*et != ':') && !isspace(*et); ++et);
        for(cp = et; isspace(*cp); ++cp);
        size_t size;

        if (*cp == ':') {
            // One Word
            tag = bt;
            etag = et;
            buf = cp + 1;
        } else {
            size = et - bt;
            if (strncmp(bt, cp, size)) {
                // <PRI>[<TIME>] <tag>_host '<tag>.<num>' : message
                if (!strncmp(bt + size - 5, "_host", 5)
                 && !strncmp(bt, cp, size - 5)) {
                    const char *b = cp;
                    cp += size - 5;
                    if (*cp == '.') {
                        while (!isspace(*++cp) && (*cp != ':'));
                        const char *e;
                        for(e = cp; isspace(*cp); ++cp);
                        if (*cp == ':') {
                            tag = b;
                            etag = e;
                            buf = cp + 1;
                        }
                    }
                } else {
                    while (!isspace(*++cp) && (*cp != ':'));
                    const char *e;
                    for(e = cp; isspace(*cp); ++cp);
                    // Two words
                    if (*cp == ':') {
                        tag = bt;
                        etag = e;
                        buf = cp + 1;
                    }
                }
            } else if (isspace(cp[size])) {
                const char *b = cp;
                cp += size;
                while (isspace(*++cp));
                // <PRI>[<TIME>] <tag> <tag> : message
                if (*cp == ':') {
                    tag = bt;
                    etag = et;
                    buf = cp + 1;
                }
            } else if (cp[size] == ':') {
                // <PRI>[<TIME>] <tag> <tag> : message
                tag = bt;
                etag = et;
                buf = cp + size + 1;
            } else if ((cp[size] == '.') || isdigit(cp[size])) {
                // <PRI>[<TIME>] <tag> '<tag>.<num>' : message
                // <PRI>[<TIME>] <tag> '<tag><num>' : message
                const char *b = cp;
                cp += size;
                while (!isspace(*++cp) && (*cp != ':'));
                const char *e = cp;
                while (isspace(*cp)) {
                    ++cp;
                }
                if (*cp == ':') {
                    tag = b;
                    etag = e;
                    buf = cp + 1;
                }
            } else {
                while (!isspace(*++cp) && (*cp != ':'));
                const char *e = cp;
                while (isspace(*cp)) {
                    ++cp;
                }
                // Two words
                if (*cp == ':') {
                    tag = bt;
                    etag = e;
                    buf = cp + 1;
                }
            }
        }
        size = etag - tag;
        if ((size <= 2)
         || ((size == 3) && !strncmp(tag, "CPU", 3))
         || ((size == 7) && !strncmp(tag, "WARNING", 7))
         || ((size == 5) && !strncmp(tag, "ERROR", 5))
         || ((size == 4) && !strncmp(tag, "INFO", 4))) {
            buf = start;
            etag = tag = "";
        }
    }
    size_t l = etag - tag;
    size_t n = 1 + l + 1 + strlen(buf) + 1;

    int rc = n;
    char *newstr = reinterpret_cast<char *>(malloc(n));
    if (!newstr) {
        rc = -ENOMEM;
    } else {
        char *np = newstr;
        switch(pri & LOG_PRIMASK) {
        case LOG_EMERG:
            // FALLTHRU
        case LOG_ALERT:
            // FALLTHRU
        case LOG_CRIT:
            *np = ANDROID_LOG_FATAL;
            break;
        case LOG_ERR:
            *np = ANDROID_LOG_ERROR;
            break;
        case LOG_WARNING:
            *np = ANDROID_LOG_WARN;
            break;
        default:
            // FALLTHRU
        case LOG_NOTICE:
            // FALLTHRU
        case LOG_INFO:
            *np = ANDROID_LOG_INFO;
            break;
        case LOG_DEBUG:
            *np = ANDROID_LOG_DEBUG;
            break;
        }
        ++np;
        strncpy(np, tag, l);
        np += l;
        *np = '\0';
        ++np;
        strcpy(np, buf);

        logbuf->log(LOG_ID_KERNEL, real, mono, uid, pid, tid, newstr,
                    (n <= USHRT_MAX) ? (unsigned short) n : USHRT_MAX);
        free(newstr);
        reader->notifyNewLog();
    }

    return rc;
}

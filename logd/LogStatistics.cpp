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

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <log/logger.h>
#include <private/android_filesystem_config.h>
#include <utils/String8.h>

#include "LogStatistics.h"

LogStatistics::LogStatistics()
        : enable(false) {
    log_id_for_each(id) {
        mSizes[id] = 0;
        mElements[id] = 0;
        mSizesTotal[id] = 0;
        mElementsTotal[id] = 0;
    }
}

namespace android {

// caller must own and free character string
static char *pidToName(pid_t pid) {
    char *retval = NULL;
    if (pid == 0) { // special case from auditd for kernel
        retval = strdup("logd.auditd");
    } else {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), "/proc/%u/cmdline", pid);
        int fd = open(buffer, O_RDONLY);
        if (fd >= 0) {
            ssize_t ret = read(fd, buffer, sizeof(buffer));
            if (ret > 0) {
                buffer[sizeof(buffer)-1] = '\0';
                // frameworks intermediate state
                if (strcmp(buffer, "<pre-initialized>")) {
                    retval = strdup(buffer);
                }
            }
            close(fd);
        }
    }
    return retval;
}

}

void LogStatistics::add(LogBufferElement *e) {
    log_id_t log_id = e->getLogId();
    unsigned short size = e->getMsgLen();
    mSizes[log_id] += size;
    ++mElements[log_id];

    uid_t uid = e->getUid();
    android::hash_t hash = android::hash_type(uid);
    typeof uidTable[0] &table = uidTable[log_id];
    ssize_t index = table.find(-1, hash, uid);
    if (index == -1) {
        UidEntry initEntry(uid);
        initEntry.add(size);
        table.add(hash, initEntry);
    } else {
        UidEntry &entry = table.editEntryAt(index);
        entry.add(size);
    }

    mSizesTotal[log_id] += size;
    ++mElementsTotal[log_id];

    if (!enable) {
        return;
    }

    pid_t pid = e->getPid();
    hash = android::hash_type(pid);
    index = pidTable.find(-1, hash, pid);
    if (index == -1) {
        PidEntry initEntry(pid, uid, android::pidToName(pid));
        initEntry.add(size);
        pidTable.add(hash, initEntry);
    } else {
        PidEntry &entry = pidTable.editEntryAt(index);
        if (entry.getUid() != uid) {
            entry.setUid(uid);
            entry.setName(android::pidToName(pid));
        } else if (!entry.getName()) {
            char *name = android::pidToName(pid);
            if (name) {
                entry.setName(name);
            }
        }
        entry.add(size);
    }
}

void LogStatistics::subtract(LogBufferElement *e) {
    log_id_t log_id = e->getLogId();
    unsigned short size = e->getMsgLen();
    mSizes[log_id] -= size;
    --mElements[log_id];

    uid_t uid = e->getUid();
    android::hash_t hash = android::hash_type(uid);
    typeof uidTable[0] &table = uidTable[log_id];
    ssize_t index = table.find(-1, hash, uid);
    if (index != -1) {
        UidEntry &entry = table.editEntryAt(index);
        if (entry.subtract(size)) {
            table.removeAt(index);
        }
    }

    if (!enable) {
        return;
    }

    pid_t pid = e->getPid();
    hash = android::hash_type(pid);
    index = pidTable.find(-1, hash, pid);
    if (index != -1) {
        PidEntry &entry = pidTable.editEntryAt(index);
        if (entry.subtract(size)) {
            pidTable.removeAt(index);
        }
    }
}

// Caller must free array
const UidEntry **LogStatistics::sort(size_t n, log_id id) {
    if (!n) {
        return NULL;
    }

    const UidEntry **retval = new const UidEntry* [n];
    memset(retval, 0, sizeof(*retval) * n);

    typeof uidTable[0] &table = uidTable[id];
    ssize_t index = -1;
    while ((index = table.next(index)) >= 0) {
        const UidEntry &entry = table.entryAt(index);
        ssize_t i = n - 1;
        size_t s = entry.getSizes();

        if (retval[i] && (s < retval[i]->getSizes())) {
            continue;
        }
        retval[i] = &entry;
        while (--i >= 0) {
            if (retval[i] && (s < retval[i]->getSizes())) {
                break;
            }
            retval[i+1] = retval[i];
            retval[i] = &entry;
        }
    }
    return retval;
}

// Caller must free array
const PidEntry **LogStatistics::sort(size_t n) {
    if (!n) {
        return NULL;
    }

    const PidEntry **retval = new const PidEntry* [n];
    memset(retval, 0, sizeof(*retval) * n);

    ssize_t index = -1;
    while ((index = pidTable.next(index)) >= 0) {
        const PidEntry &entry = pidTable.entryAt(index);
        ssize_t i = n - 1;
        size_t s = entry.getSizes();

        if (retval[i] && (s < retval[i]->getSizes())) {
            continue;
        }
        retval[i] = &entry;
        while (--i >= 0) {
            if (retval[i] && (s < retval[i]->getSizes())) {
                break;
            }
            retval[i+1] = retval[i];
            retval[i] = &entry;
        }
    }
    return retval;
}

// caller must own and free character string
char *LogStatistics::uidToName(uid_t uid) {
    // Local hard coded favourites
    if (uid == AID_LOGD) {
        return strdup("auditd");
    }

    // Android hard coded
    const struct android_id_info *info = android_ids;

    for (size_t i = 0; i < android_id_count; ++i) {
        if (info->aid == uid) {
            return strdup(info->name);
        }
        ++info;
    }

    // Pull from the package list
    extern int fdPackages;
    int fd = -1;
    if (fdPackages >= 0) {
        fd = fcntl(fdPackages, F_DUPFD, 0);
    }
    FILE *fp = NULL;
    if (fd >= 0) {
        fp = fdopen(fd, "r");
    }
    if (fp) {
        rewind(fp);
        char buffer[256];
        // This simple parser is sensitive to format changes in
        // frameworks/base/services/core/java/com/android/server/pm/Settings.java
        // A dependency note has been added to that file to correct this parser.
        bool incomplete = false;
        while (fgets(buffer, sizeof(buffer), fp)) {
            bool skip = incomplete;
            incomplete = strchr(buffer, '\n') == NULL;
            if (skip) {
                continue;
            }
            char *userId = strchr(buffer, ' ');
            if (!userId) {
                continue;
            }
            *userId = '\0';
            unsigned long value = strtoul(userId + 1, NULL, 10);
            if (value != uid) {
                continue;
            }
            fclose(fp);
            return strdup(buffer);
        }
        fclose(fp);
    }

    char *name = NULL;

    ssize_t index = -1;
    while ((index = pidTable.next(index)) != -1) {
        const PidEntry &entry = pidTable.entryAt(index);

        if (entry.getUid() == uid) {
            const char *n = entry.getName();

            if (n) {
                if (!name) {
                    name = strdup(n);
                } else if (strcmp(name, n)) {
                    free(name);
                    return NULL;
                }
            }
        }
    }

    // No one
    return name;
}

void LogStatistics::format(char **buf, uid_t uid, unsigned int logMask) {
    static const unsigned short spaces_total = 19;

    if (*buf) {
        free(*buf);
        *buf = NULL;
    }

    // Report on total logging, current and for all time

    android::String8 string("size/num");
    size_t oldLength;
    short spaces = 1;

    log_id_for_each(id) {
        if (!(logMask & (1 << id))) {
            continue;
        }
        oldLength = string.length();
        if (spaces < 0) {
            spaces = 0;
        }
        string.appendFormat("%*s%s", spaces, "", android_log_id_to_name(id));
        spaces += spaces_total + oldLength - string.length();
    }

    spaces = 4;
    string.appendFormat("\nTotal");

    log_id_for_each(id) {
        if (!(logMask & (1 << id))) {
            continue;
        }
        oldLength = string.length();
        if (spaces < 0) {
            spaces = 0;
        }
        string.appendFormat("%*s%zu/%zu", spaces, "",
                            sizesTotal(id), elementsTotal(id));
        spaces += spaces_total + oldLength - string.length();
    }

    spaces = 6;
    string.appendFormat("\nNow");

    log_id_for_each(id) {
        if (!(logMask & (1 << id))) {
            continue;
        }

        size_t els = elements(id);
        if (els) {
            oldLength = string.length();
            if (spaces < 0) {
                spaces = 0;
            }
            string.appendFormat("%*s%zu/%zu", spaces, "", sizes(id), els);
            spaces -= string.length() - oldLength;
        }
        spaces += spaces_total;
    }

    // Report on Chattiest

    // Chattiest by application (UID)
    static const size_t maximum_sorted_entries = 32;
    log_id_for_each(id) {
        if (!(logMask & (1 << id))) {
            continue;
        }

        const UidEntry **sorted = sort(maximum_sorted_entries, id);

        if (!sorted) {
            continue;
        }

        bool print = false;
        size_t len = 0;
        for(size_t index = 0; index < maximum_sorted_entries; ++index) {
            const UidEntry *entry = sorted[index];

            if (!entry) {
                continue;
            }

            size_t sizes = entry->getSizes();
            if (!sizes) {
                continue;
            }

            uid_t u = entry->getKey();
            if ((uid != AID_ROOT) && (u != uid)) {
                continue;
            }

            if (!print) {
                if (uid == AID_ROOT) {
                    string.appendFormat(
                        "\n\nChattiest UIDs in %s:\nUID%*s UID%*s\n",
                        android_log_id_to_name(id),
                        (spaces_total * 2) - 4, "Size",
                        (spaces_total * 2) - 4, "Size");
                } else {
                    string.appendFormat(
                        "\n\nLogging for your UID in %s:\n",
                        android_log_id_to_name(id));
                }
                print = true;
                len = 0;
            }

            // Line up content with two headers
            spaces = -len;
            while (spaces < 0) {
                spaces += spaces_total * 2;
            }
            android::String8 s("");
            s.appendFormat("%*s", spaces, "");
            spaces = 0;

            char *name = uidToName(u);
            android::String8 k("");
            if (name) {
                k.appendFormat("%s", name);
                free(name);
            } else {
                k.appendFormat("[%u]", u);
            }
            spaces += (spaces_total * 2) - k.length() - 1;

            android::String8 l("");
            l.appendFormat("%zu", sizes);

            while (spaces <= (ssize_t)l.length()) {
                spaces += spaces_total * 2;
            }

            android::String8 v("");
            v.appendFormat("%s%s%*s", s.string(), k.string(), spaces, l.string());
            s.setTo("");

            // Deal with line wrap
            if ((len + v.length()) > 80) {
                v.setTo("");
                v.appendFormat("%s%*s", k.string(), spaces, l.string());

                if (v.length() > 80) { // Too much to align?
                    v.setTo("");
                    v.appendFormat("%s %s", k.string(), l.string());
                }

                string.appendFormat("\n");
                len = 0;
            }
            l.setTo("");
            k.setTo("");
            string.appendFormat("%s", v.string());
            len += v.length();
        }

        delete [] sorted;
    }

    if (enable) {
        const PidEntry **sorted = sort(maximum_sorted_entries);

        if (!sorted) {
            *buf = strdup(string.string());
            return;
        }

        bool print = false;
        size_t len = 0;
        for(size_t index = 0; index < maximum_sorted_entries; ++index) {
            const PidEntry *entry = sorted[index];

            if (!entry) {
                continue;
            }

            size_t sizes = entry->getSizes();
            if (!sizes) {
                continue;
            }

            uid_t u = entry->getUid();
            if ((uid != AID_ROOT) && (u != uid)) {
                continue;
            }

            if (!print) {
                if (uid == AID_ROOT) {
                    string.appendFormat(
                        "\n\nChattiest PIDs:\nPID%*s PID%*s\n",
                        (spaces_total * 2) - 4, "Size",
                        (spaces_total * 2) - 4, "Size");
                } else {
                    string.appendFormat(
                        "\n\nLogging for your PID:\n");
                }
                print = true;
                len = 0;
            }

            // Line up content with two headers
            spaces = -len;
            while (spaces < 0) {
                spaces += spaces_total * 2;
            }
            android::String8 s("");
            s.appendFormat("%*s", spaces, "");
            spaces = 0;

            const char *name = entry->getName();
            android::String8 k("");
            if (name) {
                k.appendFormat("%s", name);
            } else {
                char *n = uidToName(u);
                if (n) {
                    k.appendFormat("%s", n);
                    free(n);
                }
            }
            k.appendFormat("[%u]", entry->getKey());
            spaces += (spaces_total * 2) - k.length() - 1;

            android::String8 v("");
            v.appendFormat("%zu", sizes);

            while (spaces <= (ssize_t)v.length()) {
                spaces += spaces_total * 2;
            }

            v.setTo("");
            v.appendFormat("%s%s%*zu", s.string(), k.string(), spaces, sizes);
            s.setTo("");

            // Deal with line wrap
            if ((len + v.length()) > 80) {
                v.setTo("");
                v.appendFormat("%s%*zu", k.string(), spaces, sizes);

                if (v.length() > 80) { // Too much to align?
                    v.setTo("");
                    v.appendFormat("%s %zu", k.string(), sizes);
                }

                string.appendFormat("\n");
                len = 0;
            }
            k.setTo("");
            string.appendFormat("%s", v.string());
            len += v.length();
        }

        delete [] sorted;
    }

    *buf = strdup(string.string());
}

namespace android {

uid_t pidToUid(pid_t pid) {
    char buffer[512];
    snprintf(buffer, sizeof(buffer), "/proc/%u/status", pid);
    FILE *fp = fopen(buffer, "r");
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp)) {
            int uid;
            if (sscanf(buffer, "Groups: %d", &uid) == 1) {
                fclose(fp);
                return uid;
            }
        }
        fclose(fp);
    }
    return getuid(); // associate this with the logger
}

}

uid_t LogStatistics::pidToUid(pid_t pid) {
    uid_t uid;
    android::hash_t hash = android::hash_type(pid);
    ssize_t index = pidTable.find(-1, hash, pid);
    if (index == -1) {
        uid = android::pidToUid(pid);
        PidEntry initEntry(pid, uid, android::pidToName(pid));
        pidTable.add(hash, initEntry);
    } else {
        PidEntry &entry = pidTable.editEntryAt(index);
        if (!entry.getName()) {
            char *name = android::pidToName(pid);
            if (name) {
                entry.setName(name);
            }
        }
        uid = entry.getUid();
    }
    return uid;
}

// caller must free character string
char *LogStatistics::pidToName(pid_t pid) {
    char *name;

    android::hash_t hash = android::hash_type(pid);
    ssize_t index = pidTable.find(-1, hash, pid);
    if (index == -1) {
        name = android::pidToName(pid);
        PidEntry initEntry(pid, android::pidToUid(pid), name ? strdup(name) : NULL);
        pidTable.add(hash, initEntry);
    } else {
        PidEntry &entry = pidTable.editEntryAt(index);
        const char *n = entry.getName();
        if (n) {
            name = strdup(n);
        } else {
            name = android::pidToName(pid);
            if (name) {
                entry.setName(strdup(name));
            }
        }
    }

    return name;
}

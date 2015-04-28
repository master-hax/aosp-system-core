/*
 * Copyright (C) 2012-2014 The Android Open Source Project
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
#include <endian.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <log/logger.h>
#include <private/android_logger.h>

#include "LogBufferElement.h"
#include "LogCommand.h"
#include "LogReader.h"

const uint64_t LogBufferElement::FLUSH_ERROR(0);
atomic_int_fast64_t LogBufferElement::sequence;

LogBufferElement::LogBufferElement(log_id_t log_id, log_time realtime,
                                   uid_t uid, pid_t pid, pid_t tid,
                                   const char *msg, unsigned short len)
        : mLogId(log_id)
        , mUid(uid)
        , mPid(pid)
        , mTid(tid)
        , mMsgLen(len)
        , mSequence(sequence.fetch_add(1, memory_order_relaxed))
        , mRealTime(realtime) {
    mMsg = new char[len];
    memcpy(mMsg, msg, len);
}

LogBufferElement::~LogBufferElement() {
    delete [] mMsg;
}

// caller must own and free character string
static char *tidToName(pid_t tid) {
    char *retval = NULL;
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "/proc/%u/comm", tid);
    int fd = open(buffer, O_RDONLY);
    if (fd >= 0) {
        ssize_t ret = read(fd, buffer, sizeof(buffer));
        if (ret >= (ssize_t)sizeof(buffer)) {
            ret = sizeof(buffer) - 1;
        }
        while ((ret > 0) && isspace(buffer[ret - 1])) {
            --ret;
        }
        if (ret > 0) {
            buffer[ret] = '\0';
            retval = strdup(buffer);
        }
        close(fd);
    }

    // if nothing for comm, check out cmdline
    char *name = android::pidToName(tid);
    if (!retval) {
        retval = name;
        name = NULL;
    }

    // check if comm is truncated, see if cmdline has full representation
    if (name) {
        // impossible for retval to be NULL if name not NULL
        size_t retval_len = strlen(retval);
        size_t name_len = strlen(name);
        // KISS: ToDo: Only checks prefix truncated, not suffix, or both
        if ((retval_len < name_len) && !strcmp(retval, name + name_len - retval_len)) {
            free(retval);
            retval = name;
        } else {
            free(name);
        }
    }
    return retval;
}

// assumption: mMsg == NULL
size_t LogBufferElement::populateDroppedMessage(char *&buffer,
        LogBuffer *parent, unsigned long expired) {
    static const char tag[] = "logd";
    static const char format_uid[] = "uid=%u%s too chatty%s, expire %lu line%s";

    char *name = parent->uidToName(mUid);
    char *commName = tidToName(mTid);
    if (!commName && (mTid != mPid)) {
        commName = tidToName(mPid);
    }
    if (!commName) {
        commName = parent->pidToName(mPid);
    }
    if (name && commName && !strcmp(name, commName)) {
        free(commName);
        commName = NULL;
    }
    if (name) {
        char *p = NULL;
        asprintf(&p, "(%s)", name);
        if (p) {
            free(name);
            name = p;
        }
    }
    if (commName) {
        char *p = NULL;
        asprintf(&p, " comm=%s", commName);
        if (p) {
            free(commName);
            commName = p;
        }
    }
    // identical to below to calculate the buffer size required
    size_t len = snprintf(NULL, 0, format_uid, mUid, name ? name : "",
                          commName ? commName : "",
                          expired, (expired > 1) ? "s" : "");

    size_t hdrLen;
    if (mLogId == LOG_ID_EVENTS) {
        hdrLen = sizeof(android_log_event_string_t);
    } else {
        hdrLen = 1 + sizeof(tag);
    }

    buffer = static_cast<char *>(calloc(1, hdrLen + len + 1));
    if (!buffer) {
        free(name);
        free(commName);
        return 0;
    }

    size_t retval = hdrLen + len;
    if (mLogId == LOG_ID_EVENTS) {
        android_log_event_string_t *e = reinterpret_cast<android_log_event_string_t *>(buffer);

        e->header.tag = htole32(LOGD_LOG_TAG);
        e->type = EVENT_TYPE_STRING;
        e->length = htole32(len);
    } else {
        ++retval;
        buffer[0] = ANDROID_LOG_INFO;
        strcpy(buffer + 1, tag);
    }

    snprintf(buffer + hdrLen, len + 1, format_uid, mUid, name ? name : "",
             commName ? commName : "",
             expired, (expired > 1) ? "s" : "");
    free(name);
    free(commName);

    return retval;
}

// Define a temporary mechanism to hold on to the total expire count
// for the specified lid, uid, pid and tid.
class LogBufferElementKey {
    const union {
        struct {
            uint16_t lid;
            uint16_t uid;
            uint16_t pid;
            uint16_t tid;
        } __packed;
        uint64_t value;
    } __packed;

public:
    LogBufferElementKey(LogBufferElement *e):
        lid(e->getLogId()),
        uid(e->getUid()),
        pid(e->getPid()),
        tid(e->getTid()) { }
    LogBufferElementKey(uint64_t key):value(key) { }

    uint64_t getKey() { return value; }
    uint16_t getLid() { return lid; }
    uint16_t getUid() { return uid; }
    uint16_t getPid() { return pid; }
    uint16_t getTid() { return tid; }
};

class LogToExpire {
    const uint64_t key;
    unsigned long expired;

public:
    LogToExpire(LogBufferElement *e):
        key(LogBufferElementKey(e).getKey()),
        expired(e->getDropped()) { }

    const uint64_t&getKey() const { return key; }

    unsigned long getExpired() const { return expired; }
    void add(LogBufferElement *e) { expired += e->getDropped(); }
};

class LogBufferElementLast : public android::BasicHashtable<uint64_t, LogToExpire> { };

void LogBufferElement::flushEnd(SocketClient *reader, LogBuffer *parent, void **priv) {
    LogBufferElementLast *last = reinterpret_cast<LogBufferElementLast *>(*priv);
    if (!last) {
        return;
    }

    ssize_t index = last->next(-1);
    if (index == -1) {
        delete last;
        *priv = NULL;
        return;
    }

    log_time realtime(CLOCK_REALTIME);
    struct logger_entry_v3 entry;
    memset(&entry, 0, sizeof(struct logger_entry_v3));
    entry.hdr_size = sizeof(struct logger_entry_v3);

    do {
        const LogToExpire &l = last->entryAt(index);
        if (l.getExpired() < 4) { // Small complicit stuff is just noise
            last->removeAt(index);
            continue;
        }

        LogBufferElementKey key(l.getKey());
        entry.lid = key.getLid();
        entry.pid = key.getPid();
        entry.tid = key.getTid();
        entry.sec = realtime.tv_sec;
        entry.nsec = realtime.tv_nsec;
        struct iovec iovec[2];
        iovec[0].iov_base = &entry;
        iovec[0].iov_len = sizeof(struct logger_entry_v3);

        char *buffer = NULL;
        entry.len = LogBufferElement((log_id_t)key.getLid(),
                                     realtime,
                                     key.getUid(),
                                     key.getPid(),
                                     key.getTid(),
                                     NULL,
                                     0).populateDroppedMessage(buffer,
                                                               parent,
                                                               l.getExpired());
        if (entry.len) {
            iovec[1].iov_base = buffer;
            iovec[1].iov_len = entry.len;

            reader->sendDatav(iovec, 2);
        }
        free(buffer);
        last->removeAt(index);
    } while ((index = last->next(-1)) != -1);

    delete last;
    *priv = NULL;
}

uint64_t LogBufferElement::flushTo(SocketClient *reader, LogBuffer *parent, void **priv) {
    struct logger_entry_v3 entry;

    // This is one of the dropped-count messages
    if (!mMsg) {
        if (!*priv) {
            *priv = new LogBufferElementLast;
        }
        LogBufferElementLast *last = reinterpret_cast<LogBufferElementLast *>(*priv);
        uint64_t key = LogBufferElementKey(this).getKey();
        android::hash_t hash = android::hash_type(key);
        ssize_t index = last->find(-1, hash, key);
        if (index == -1) {
            last->add(hash, LogToExpire(this));
        } else {
            last->editEntryAt(index).add(this);
        }
        return mSequence;
    }

    memset(&entry, 0, sizeof(struct logger_entry_v3));

    entry.hdr_size = sizeof(struct logger_entry_v3);
    entry.lid = mLogId;
    entry.pid = mPid;
    entry.tid = mTid;
    entry.sec = mRealTime.tv_sec;
    entry.nsec = mRealTime.tv_nsec;

    struct iovec iovec[2];
    iovec[0].iov_base = &entry;
    iovec[0].iov_len = sizeof(struct logger_entry_v3);

    // Did we have an associated drop-count message?
    LogBufferElementLast *last = reinterpret_cast<LogBufferElementLast *>(*priv);
    if (last) {
        uint64_t key = LogBufferElementKey(this).getKey();
        android::hash_t hash = android::hash_type(key);
        ssize_t index = last->find(-1, hash, key);
        if (index != -1) {
            char *buffer = NULL;
            entry.len = populateDroppedMessage(buffer, parent,
	        last->entryAt(index).getExpired());
            last->removeAt(index);
            if (entry.len) {
                iovec[1].iov_base = buffer;
                iovec[1].iov_len = entry.len;

                reader->sendDatav(iovec, 2);
            }
            free(buffer);
        }
    }

    entry.len = mMsgLen;
    iovec[1].iov_base = mMsg;
    iovec[1].iov_len = entry.len;

    return reader->sendDatav(iovec, 2) ? FLUSH_ERROR : mSequence;
}

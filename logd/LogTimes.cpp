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

#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>

#include <log/logger.h>
#include <private/android_logger.h>

#include "FlushCommand.h"
#include "LogBuffer.h"
#include "LogTimes.h"
#include "LogReader.h"

pthread_mutex_t LogTimeEntry::timesLock = PTHREAD_MUTEX_INITIALIZER;

const struct timespec LogTimeEntry::EPOCH = { 0, 1 };

LogTimeEntry::LogTimeEntry(LogReader &reader, SocketClient *client,
                           bool nonBlock, unsigned long tail,
                           unsigned int logMask, pid_t pid,
                           log_time start)
        : mRefCount(1)
        , mRelease(false)
        , mError(false)
        , threadRunning(false)
        , mReader(reader)
        , mLogMask(logMask)
        , mPid(pid)
        , mCount(0)
        , mTail(tail)
        , mIndex(0)
        , mClient(client)
        , mStart(start)
        , mNonBlock(nonBlock)
        , mEnd(CLOCK_MONOTONIC)
{
        pthread_cond_init(&threadTriggeredCondition, NULL);
        cleanSkip_Locked();
}

void LogTimeEntry::startReader_Locked(void) {
    pthread_attr_t attr;

    threadRunning = true;

    if (!pthread_attr_init(&attr)) {
        if (!pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
            if (!pthread_create(&mThread, &attr,
                                LogTimeEntry::threadStart, this)) {
                pthread_attr_destroy(&attr);
                return;
            }
        }
        pthread_attr_destroy(&attr);
    }
    threadRunning = false;
    if (mClient) {
        mClient->decRef();
    }
    decRef_Locked();
}

void LogTimeEntry::threadStop(void *obj) {
    LogTimeEntry *me = reinterpret_cast<LogTimeEntry *>(obj);

    lock();

    if (me->mNonBlock) {
        me->error_Locked();
    }

    SocketClient *client = me->mClient;

    if (me->isError_Locked()) {
        LogReader &reader = me->mReader;
        LastLogTimes &times = reader.logbuf().mTimes;

        LastLogTimes::iterator it = times.begin();
        while(it != times.end()) {
            if (*it == me) {
                times.erase(it);
                me->release_Locked();
                break;
            }
            it++;
        }

        me->mClient = NULL;
        reader.release(client);
    }

    if (client) {
        client->decRef();
    }

    me->threadRunning = false;
    me->decRef_Locked();

    unlock();
}

void *LogTimeEntry::threadStart(void *obj) {
    prctl(PR_SET_NAME, "logd.reader.per");

    LogTimeEntry *me = reinterpret_cast<LogTimeEntry *>(obj);

    pthread_cleanup_push(threadStop, obj);

    SocketClient *client = me->mClient;
    if (!client) {
        me->error();
        return NULL;
    }

    LogBuffer &logbuf = me->mReader.logbuf();

    bool privileged = FlushCommand::hasReadLogs(client);

    lock();

    while (me->threadRunning && !me->isError_Locked()) {
        log_time start = me->mStart;

        unlock();

        if (me->mTail) {
            logbuf.flushTo(client, start, privileged, FilterFirstPass, me);
        }
        start = logbuf.flushTo(client, start, privileged, FilterSecondPass, me);

        lock();

        if (start == LogBufferElement::FLUSH_ERROR) {
            me->error_Locked();
        }

        if (me->mNonBlock || !me->threadRunning || me->isError_Locked()) {
            break;
        }

        me->cleanSkip_Locked();

        pthread_cond_wait(&me->threadTriggeredCondition, &timesLock);
    }

    unlock();

    pthread_cleanup_pop(true);

    return NULL;
}

// A first pass to count the number of elements
bool LogTimeEntry::FilterFirstPass(const LogBufferElement *element, void *obj) {
    LogTimeEntry *me = reinterpret_cast<LogTimeEntry *>(obj);

    LogTimeEntry::lock();

    if (me->mCount == 0) {
        me->mStart = element->getMonotonicTime();
    }

    if ((!me->mPid || (me->mPid == element->getPid()))
            && (me->isWatching(element->getLogId()))) {
        ++me->mCount;
    }

    LogTimeEntry::unlock();

    return false;
}

// A second pass to send the selected elements
bool LogTimeEntry::FilterSecondPass(const LogBufferElement *element, void *obj) {
    LogTimeEntry *me = reinterpret_cast<LogTimeEntry *>(obj);
    log_id_t id = element->getLogId();

    LogTimeEntry::lock();

    me->mStart = element->getMonotonicTime();

    if (me->skipAhead[id]) {
        me->skipAhead[id]--;
        goto skip;
    }

    // Truncate to close race between first and second pass
    if (me->mNonBlock && me->mTail && (me->mIndex >= me->mCount)) {
        goto skip;
    }

    if (!me->isWatching(id)) {
        goto skip;
    }

    if (me->mPid && (me->mPid != element->getPid())) {
        goto skip;
    }

    if (me->isError_Locked()) {
        goto skip;
    }

    if (!me->mTail) {
        goto ok;
    }

    ++me->mIndex;

    if ((me->mCount > me->mTail) && (me->mIndex <= (me->mCount - me->mTail))) {
        goto skip;
    }

    if (!me->mNonBlock) {
        me->mTail = 0;
    }

ok:
    if (!me->skipAhead[id]) {
        // Check if this is the first UID per logid message buffer
        uid_t uid = element->getUid();
        android::hash_t hash = android::hash_type(uid);
        bool found = me->mTable[id].find(-1, hash, uid) != -1;
        if (!found) {
            TEntry initEntry(uid);
            me->mTable[id].add(hash, initEntry);
        }
        SocketClient *reader = me->mClient;
        LogTimeEntry::unlock();

        if (found) {
            return true;
        }

        // Inject first UID per logid message buffer
        static const char format[] = "UID:%d";
        const char *msg = element->getMsg();
        size_t hdrlen = (id == LOG_ID_EVENTS)
            ? sizeof(android_log_event_string_t)
            : (strlen(msg + 1) + 2);
        size_t len = snprintf(NULL, 0, format, uid);

        struct entry {
            struct logger_entry_v3 header;
            union {
                android_log_event_string_t event;
                char message[];
            } msg;
        } *entry;

        entry = static_cast<struct entry *>(
                    calloc(1, sizeof(entry->header) + hdrlen + len + 1));
        if (!entry) {
            return true;
        }

        entry->header.hdr_size = sizeof(entry->header);
        entry->header.len = hdrlen + len;
        entry->header.lid = id;
        entry->header.pid = element->getPid();
        entry->header.tid = element->getTid();
        log_time realtime = element->getRealTime();
        entry->header.sec = realtime.tv_sec;
        entry->header.nsec = realtime.tv_nsec;
        if (id == LOG_ID_EVENTS) {
            entry->msg.event.header.tag = ((const android_event_header_t *)msg)->tag;
            entry->msg.event.payload.type = EVENT_TYPE_STRING;
            entry->msg.event.payload.length = htole32(len);
        } else {
            // Text messages must have terminating nul in count
            entry->header.len++;
            entry->msg.message[0] = ANDROID_LOG_INFO;
            strcpy(entry->msg.message + 1, msg + 1);
        }
        snprintf(entry->msg.message + hdrlen, len + 1, format, uid);

        reader->sendData(entry, sizeof(entry->header) + hdrlen + len);

        free(entry);

        return true;
    }
    // FALLTHRU

skip:
    LogTimeEntry::unlock();
    return false;
}

void LogTimeEntry::cleanSkip_Locked(void) {
    for (log_id_t i = LOG_ID_MIN; i < LOG_ID_MAX; i = (log_id_t) (i + 1)) {
        skipAhead[i] = 0;
    }
}

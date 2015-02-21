/*
 * Copyright (C) 2008-2014 The Android Open Source Project
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
/*
 * Intercepts log messages intended for the Android log device.
 * When running in the context of the simulator, the messages are
 * passed on to the underlying (fake) log device.  When not in the
 * simulator, messages are printed to stderr.
 */
#include "stderr_log.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include <log/logd.h>

#if !defined(_WIN32)
#include <pthread.h>
#endif

#ifndef __unused
#define __unused __attribute__((__unused__))
#endif

#define kMaxTagLen  16      /* from the long-dead utils/Log.cpp */

#define kTagSetSize 16      /* arbitrary */

#if 0
#define TRACE(...) printf("stderr_log: " __VA_ARGS__)
#else
#define TRACE(...) ((void)0)
#endif

#if !defined(_WIN32)
/*
 * Locking.  Since we're emulating a device, we need to be prepared
 * to have multiple callers at the same time.  This lock is used
 * to both protect the fd list and to prevent LogStates from being
 * freed out from under a user.
 */
static pthread_mutex_t fakeLogDeviceLock = PTHREAD_MUTEX_INITIALIZER;

static void lock()
{
    pthread_mutex_lock(&fakeLogDeviceLock);
}

static void unlock()
{
    pthread_mutex_unlock(&fakeLogDeviceLock);
}
#else   // !defined(_WIN32)
#define lock() ((void)0)
#define unlock() ((void)0)
#endif  // !defined(_WIN32)

// Log tags, as parsed from the ANDROID_LOG_TAGS environment variable.
typedef struct LogTags {
    int globalMinPriority;
    struct {
        char tag[kMaxTagLen];
        int minPriority;
    } tagSet[kTagSetSize];
} LogTags;

static LogTags* logTags;

/*
 * Configure logging based on ANDROID_LOG_TAGS environment variable.  We
 * need to parse a string that looks like
 *
 *   *:v jdwp:d dalvikvm:d dalvikvm-gc:i dalvikvmi:i
 *
 * The tag (or '*' for the global level) comes first, followed by a colon
 * and a letter indicating the minimum priority level we're expected to log.
 * This can be used to reveal or conceal logs with specific tags.
 *
 * TODO: There seem to be multiple copies of this code floating around.
 * Should we cull ?
 */
static void configureLogTags()
{
    if (logTags != NULL) {
        return;
    }

    logTags = calloc(1, sizeof(LogTags));

    /* global min priority defaults to "info" level */
    logTags->globalMinPriority = ANDROID_LOG_INFO;

    /*
     * This is based on the the long-dead utils/Log.cpp code.
     */
    const char* tags = getenv("ANDROID_LOG_TAGS");
    TRACE("Found ANDROID_LOG_TAGS='%s'\n", tags);
    if (tags != NULL) {
        int entry = 0;

        while (*tags != '\0') {
            char tagName[kMaxTagLen];
            int i, minPrio;

            while (isspace(*tags))
                tags++;

            i = 0;
            while (*tags != '\0' && !isspace(*tags) && *tags != ':' &&
                i < kMaxTagLen)
            {
                tagName[i++] = *tags++;
            }
            if (i == kMaxTagLen) {
                TRACE("ERROR: env tag too long (%d chars max)\n", kMaxTagLen-1);
                return;
            }
            tagName[i] = '\0';

            /* default priority, if there's no ":" part; also zero out '*' */
            minPrio = ANDROID_LOG_VERBOSE;
            if (tagName[0] == '*' && tagName[1] == '\0') {
                minPrio = ANDROID_LOG_DEBUG;
                tagName[0] = '\0';
            }

            if (*tags == ':') {
                tags++;
                if (*tags >= '0' && *tags <= '9') {
                    if (*tags >= ('0' + ANDROID_LOG_SILENT))
                        minPrio = ANDROID_LOG_VERBOSE;
                    else
                        minPrio = *tags - '\0';
                } else {
                    switch (*tags) {
                    case 'v':   minPrio = ANDROID_LOG_VERBOSE;  break;
                    case 'd':   minPrio = ANDROID_LOG_DEBUG;    break;
                    case 'i':   minPrio = ANDROID_LOG_INFO;     break;
                    case 'w':   minPrio = ANDROID_LOG_WARN;     break;
                    case 'e':   minPrio = ANDROID_LOG_ERROR;    break;
                    case 'f':   minPrio = ANDROID_LOG_FATAL;    break;
                    case 's':   minPrio = ANDROID_LOG_SILENT;   break;
                    default:    minPrio = ANDROID_LOG_DEFAULT;  break;
                    }
                }

                tags++;
                if (*tags != '\0' && !isspace(*tags)) {
                    TRACE("ERROR: garbage in tag env; expected whitespace\n");
                    TRACE("       env='%s'\n", tags);
                    return;
                }
            }

            if (tagName[0] == 0) {
                logTags->globalMinPriority = minPrio;
                TRACE("+++ global min prio %d\n", logState->globalMinPriority);
            } else {
                logTags->tagSet[entry].minPriority = minPrio;
                strcpy(logTags->tagSet[entry].tag, tagName);
                TRACE("+++ entry %d: %s:%d\n",
                    entry,
                    logTags->tagSet[entry].tag,
                    logTags->tagSet[entry].minPriority);
                entry++;
            }
        }
    }
}

/*
 * Return a human-readable string for the priority level.  Always returns
 * a valid string.
 */
static const char* getPriorityString(int priority)
{
    /* the first character of each string should be unique */
    static const char* priorityStrings[] = {
        "Verbose", "Debug", "Info", "Warn", "Error", "Assert"
    };
    int idx;

    idx = (int) priority - (int) ANDROID_LOG_VERBOSE;
    if (idx < 0 ||
        idx >= (int) (sizeof(priorityStrings) / sizeof(priorityStrings[0])))
        return "?unknown?";
    return priorityStrings[idx];
}

#if defined(_WIN32)
/*
 * WIN32 does not have writev().
 * Make up something to replace it.
 */
static ssize_t fake_writev(int fd, const struct iovec *iov, int iovcnt) {
    ssize_t result = 0;
    const struct iovec* end = iov + iovcnt;
    for (; iov < end; iov++) {
        ssize_t w = write(fd, iov->iov_base, iov->iov_len);
        if (w != (ssize_t) iov->iov_len) {
            if (w < 0)
                return w;
            return result + w;
        }
        result += w;
    }
    return result;
}

#define writev fake_writev
#endif


/*
 * Write a filtered log message to stderr.
 *
 * Log format parsing taken from the long-dead utils/Log.cpp.
 */
static void showLog(int logPrio, const char* tag, const char* msg)
{
#if !defined(_WIN32)
    struct tm tmBuf;
#endif
    struct tm* ptm;
    char timeBuf[32];
    char prefixBuf[128], suffixBuf[128];
    char priChar;
    time_t when;
    pid_t pid, tid;

    TRACE("LOG %d: %s %s", logPrio, tag, msg);

    priChar = getPriorityString(logPrio)[0];
    when = time(NULL);
    pid = tid = getpid();       // find gettid()?

    /*
     * Get the current date/time in pretty form
     *
     * It's often useful when examining a log with "less" to jump to
     * a specific point in the file by searching for the date/time stamp.
     * For this reason it's very annoying to have regexp meta characters
     * in the time stamp.  Don't use forward slashes, parenthesis,
     * brackets, asterisks, or other special chars here.
     */
#if !defined(_WIN32)
    ptm = localtime_r(&when, &tmBuf);
#else
    ptm = localtime(&when);
#endif
    //strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", ptm);
    strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", ptm);

    /*
     * Construct a buffer containing the log header and log message.
     */
    const size_t prefixLen = snprintf(
        prefixBuf, sizeof(prefixBuf), "[ %s %5d:%5d %c/%-8s ]\n",
        timeBuf, pid, tid, priChar, tag);
    strcpy(suffixBuf, "\n\n");

    const size_t suffixLen = 2;

    /*
     * Figure out how many lines there will be.
     */
    const char* end = msg + strlen(msg);
    size_t numLines = 0;
    const char* p = msg;
    while (p < end) {
        if (*p++ == '\n') numLines++;
    }
    if (p > msg && *(p-1) != '\n') numLines++;

    /*
     * Create an array of iovecs large enough to write all of
     * the lines with a prefix and a suffix.
     */
    const size_t INLINE_VECS = 6;
    const size_t MAX_LINES   = ((size_t)~0)/(3*sizeof(struct iovec*));
    struct iovec stackVec[INLINE_VECS];
    struct iovec* vec = stackVec;
    size_t numVecs;

    if (numLines > MAX_LINES)
        numLines = MAX_LINES;

    numVecs = numLines*3;  // 3 iovecs per line.
    if (numVecs > INLINE_VECS) {
        vec = (struct iovec*)malloc(sizeof(struct iovec)*numVecs);
        if (vec == NULL) {
            msg = "LOG: write failed, no memory";
            numVecs = 3;
            numLines = 1;
            vec = stackVec;
        }
    }

    /*
     * Fill in the iovec pointers.
     */
    p = msg;
    struct iovec* v = vec;
    int totalLen = 0;
    while (numLines > 0 && p < end) {
        if (prefixLen > 0) {
            v->iov_base = prefixBuf;
            v->iov_len = prefixLen;
            totalLen += prefixLen;
            v++;
        }
        const char* start = p;
        while (p < end && *p != '\n') p++;
        if ((p-start) > 0) {
            v->iov_base = (void*)start;
            v->iov_len = p-start;
            totalLen += p-start;
            v++;
        }
        if (*p == '\n') p++;
        if (suffixLen > 0) {
            v->iov_base = suffixBuf;
            v->iov_len = suffixLen;
            totalLen += suffixLen;
            v++;
        }
        numLines -= 1;
    }
    
    /*
     * Write the entire message to the log file with a single writev() call.
     * We need to use this rather than a collection of printf()s on a FILE*
     * because of multi-threading and multi-process issues.
     *
     * If the file was not opened with O_APPEND, this will produce interleaved
     * output when called on the same file from multiple processes.
     *
     * If the file descriptor is actually a network socket, the writev()
     * call may return with a partial write.  Putting the writev() call in
     * a loop can result in interleaved data.  This can be alleviated
     * somewhat by wrapping the writev call in the Mutex.
     */

    for(;;) {
        int cc = writev(fileno(stderr), vec, v-vec);

        if (cc == totalLen) break;
        
        if (cc < 0) {
            if(errno == EINTR) continue;
            
                /* can't really log the failure; for now, throw out a stderr */
            fprintf(stderr, "+++ LOG: write failed (errno=%d)\n", errno);
            break;
        } else {
                /* shouldn't happen when writing to file or tty */
            fprintf(stderr, "+++ LOG: write partial (%d of %d)\n", cc, totalLen);
            break;
        }
    }

    /* if we allocated storage for the iovecs, free it */
    if (vec != stackVec)
        free(vec);
}


/*
 * Receive a log message.  We happen to know that "vector" has three parts:
 *
 *  priority (1 byte)
 *  tag (N bytes -- null-terminated ASCII string)
 *  message (N bytes -- null-terminated ASCII string)
 */
ssize_t write_to_stderr(log_id_t log_id, const struct iovec* vector, int count)
{
    /* Make sure that no-one frees the LogState while we're using it.
     * Also guarantees that only one thread is in showLog() at a given
     * time (if it matters).
     */
    lock();

    if (logTags == NULL) {
      configureLogTags();
    }

    if (log_id == LOG_ID_EVENTS) {
        TRACE("%s: ignoring binary log for events\n");
        goto bail;
    }

    if (count != 3) {
        TRACE("%d: writevLog with count=%d not expected\n", log_id, count);
        goto error;
    }

    /* pull out the three fields */
    int logPrio = *(const char*)vector[0].iov_base;
    const char* tag = (const char*) vector[1].iov_base;
    const char* msg = (const char*) vector[2].iov_base;

    /* see if this log tag is configured */
    int i;
    int minPrio = logTags->globalMinPriority;
    for (i = 0; i < kTagSetSize; i++) {
        if (logTags->tagSet[i].minPriority == ANDROID_LOG_UNKNOWN)
            break;      /* reached end of configured values */

        if (strcmp(logTags->tagSet[i].tag, tag) == 0) {
            //TRACE("MATCH tag '%s'\n", tag);
            minPrio = logTags->tagSet[i].minPriority;
            break;
        }
    }

    if (logPrio >= minPrio) {
        showLog(logPrio, tag, msg);
    } else {
        //TRACE("+++ NOLOG(%d): %s %s", logPrio, tag, msg);
    }

bail:
    unlock();
    return vector[0].iov_len + vector[1].iov_len + vector[2].iov_len;
error:
    unlock();
    return -1;
}

int __android_log_is_loggable(int prio, const char *tag __unused, int def)
{
    int logLevel = def;
    return logLevel >= 0 && prio >= logLevel;
}

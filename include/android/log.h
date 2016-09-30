/*
 * Copyright (C) 2009 The Android Open Source Project
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

#ifndef _ANDROID_LOG_H
#define _ANDROID_LOG_H

/******************************************************************
 *
 * IMPORTANT NOTICE:
 *
 *   This file is part of Android's set of stable system headers
 *   exposed by the Android NDK (Native Development Kit) since
 *   platform release 1.5
 *
 *   Third-party source AND binary code relies on the definitions
 *   here to be FROZEN ON ALL UPCOMING PLATFORM RELEASES.
 *
 *   - DO NOT MODIFY ENUMS (EXCEPT IF YOU ADD NEW 32-BIT VALUES)
 *   - DO NOT MODIFY CONSTANTS OR FUNCTIONAL MACROS
 *   - DO NOT CHANGE THE SIGNATURE OF FUNCTIONS IN ANY WAY
 *   - DO NOT CHANGE THE LAYOUT OR SIZE OF STRUCTURES
 */

/*
 * Support routines to send messages to the Android in-kernel log buffer,
 * which can later be accessed through the 'logcat' utility.
 *
 * Each log message must have
 *   - a priority
 *   - a log tag
 *   - some text
 *
 * The tag normally corresponds to the component that emits the log message,
 * and should be reasonably small.
 *
 * Log message text may be truncated to less than an implementation-specific
 * limit (e.g. 1023 characters max).
 *
 * Note that a newline character ("\n") will be appended automatically to your
 * log message, if not already there. It is not possible to send several messages
 * and have them appear on a single line in logcat.
 *
 * PLEASE USE LOGS WITH MODERATION:
 *
 *  - Sending log messages eats CPU and slow down your application and the
 *    system.
 *
 *  - The circular log buffer is pretty small (<64KB), sending many messages
 *    might push off other important log messages from the rest of the system.
 *
 *  - In release builds, only send log messages to account for exceptional
 *    conditions.
 *
 * NOTE: These functions MUST be implemented by /system/lib/liblog.so
 */

#if !defined(_WIN32)
#include <pthread.h>
#endif
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C++" {
#include <string>
}
#endif

#include <log/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Android log priority values, in ascending priority order.
 */
typedef enum android_LogPriority {
    ANDROID_LOG_UNKNOWN = 0,
    ANDROID_LOG_DEFAULT,    /* only for SetMinPriority() */
    ANDROID_LOG_VERBOSE,
    ANDROID_LOG_DEBUG,
    ANDROID_LOG_INFO,
    ANDROID_LOG_WARN,
    ANDROID_LOG_ERROR,
    ANDROID_LOG_FATAL,
    ANDROID_LOG_SILENT,     /* only for SetMinPriority(); must be last */
} android_LogPriority;

/*
 * Release any logger resources (a new log write will immediately re-acquire)
 */
void __android_log_close();

/*
 * Send a simple string to the log.
 */
int __android_log_write(int prio, const char *tag, const char *text);

/*
 * Send a formatted string to the log, used like printf(fmt,...)
 */
int __android_log_print(int prio, const char *tag,  const char *fmt, ...)
#if defined(__GNUC__)
#ifdef __USE_MINGW_ANSI_STDIO
#if __USE_MINGW_ANSI_STDIO
    __attribute__ ((format(gnu_printf, 3, 4)))
#else
    __attribute__ ((format(printf, 3, 4)))
#endif
#else
    __attribute__ ((format(printf, 3, 4)))
#endif
#endif
    ;

/*
 * A variant of __android_log_print() that takes a va_list to list
 * additional parameters.
 */
int __android_log_vprint(int prio, const char *tag,
                         const char *fmt, va_list ap);

/*
 * Log an assertion failure and abort the process to have a chance
 * to inspect it if a debugger is attached. This uses the FATAL priority.
 */
void __android_log_assert(const char *cond, const char *tag,
                          const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__ ((__noreturn__))
#ifdef __USE_MINGW_ANSI_STDIO
#if __USE_MINGW_ANSI_STDIO
    __attribute__ ((format(gnu_printf, 3, 4)))
#else
    __attribute__ ((format(printf, 3, 4)))
#endif
#else
    __attribute__ ((format(printf, 3, 4)))
#endif
#endif
    ;

/*
 * C/C++ logging functions.  See the logging documentation for API details.
 *
 * We'd like these to be available from C code (in case we import some from
 * somewhere), so this has a C interface.
 *
 * The output will be correct when the log file is shared between multiple
 * threads and/or multiple processes so long as the operating system
 * supports O_APPEND.  These calls have mutex-protected data structures
 * and so are NOT reentrant.  Do not use LOG in a signal handler.
 */

/*
 * This file uses ", ## __VA_ARGS__" zero-argument token pasting to
 * work around issues with debug-only syntax errors in assertions
 * that are missing format strings.  See commit
 * 19299904343daf191267564fe32e6cd5c165cd42
 */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif

int __android_log_bwrite(int32_t tag, const void *payload, size_t len);
int __android_log_btwrite(int32_t tag, char type, const void *payload,
                          size_t len);
int __android_log_bswrite(int32_t tag, const char *payload);

int __android_log_security_bwrite(int32_t tag, const void *payload, size_t len);
int __android_log_security_bswrite(int32_t tag, const char *payload);

/* --------------------------------------------------------------------- */

/*
 * Normally we strip ALOGV (VERBOSE messages) from release builds.
 * You can modify this (for example with "#define LOG_NDEBUG 0"
 * at the top of your source file) to change that behavior.
 */
#ifndef LOG_NDEBUG
#ifdef NDEBUG
#define LOG_NDEBUG 1
#else
#define LOG_NDEBUG 0
#endif
#endif

/*
 * This is the local tag used for the following simplified
 * logging macros.  You can change this preprocessor definition
 * before using the other macros to change the tag.
 */
#ifndef LOG_TAG
#define LOG_TAG NULL
#endif

/* --------------------------------------------------------------------- */

#ifndef __predict_false
#define __predict_false(exp) __builtin_expect((exp) != 0, 0)
#endif

/*
 *      -DLINT_RLOG in sources that you want to enforce that all logging
 * goes to the radio log buffer. If any logging goes to any of the other
 * log buffers, there will be a compile or link error to highlight the
 * problem. This is not a replacement for a full audit of the code since
 * this only catches compiled code, not ifdef'd debug code. Options to
 * defining this, either temporarily to do a spot check, or permanently
 * to enforce, in all the communications trees; We have hopes to ensure
 * that by supplying just the radio log buffer that the communications
 * teams will have their one-stop shop for triaging issues.
 */
#ifndef LINT_RLOG

/*
 * Simplified macro to send a verbose log message using the current LOG_TAG.
 */
#ifndef ALOGV
#define __ALOGV(...) ((void)ALOG(LOG_VERBOSE, LOG_TAG, __VA_ARGS__))
#if LOG_NDEBUG
#define ALOGV(...) do { if (0) { __ALOGV(__VA_ARGS__); } } while (0)
#else
#define ALOGV(...) __ALOGV(__VA_ARGS__)
#endif
#endif

#ifndef ALOGV_IF
#if LOG_NDEBUG
#define ALOGV_IF(cond, ...)   ((void)0)
#else
#define ALOGV_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)ALOG(LOG_VERBOSE, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif
#endif

/*
 * Simplified macro to send a debug log message using the current LOG_TAG.
 */
#ifndef ALOGD
#define ALOGD(...) ((void)ALOG(LOG_DEBUG, LOG_TAG, __VA_ARGS__))
#endif

#ifndef ALOGD_IF
#define ALOGD_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)ALOG(LOG_DEBUG, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

/*
 * Simplified macro to send an info log message using the current LOG_TAG.
 */
#ifndef ALOGI
#define ALOGI(...) ((void)ALOG(LOG_INFO, LOG_TAG, __VA_ARGS__))
#endif

#ifndef ALOGI_IF
#define ALOGI_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)ALOG(LOG_INFO, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

/*
 * Simplified macro to send a warning log message using the current LOG_TAG.
 */
#ifndef ALOGW
#define ALOGW(...) ((void)ALOG(LOG_WARN, LOG_TAG, __VA_ARGS__))
#endif

#ifndef ALOGW_IF
#define ALOGW_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)ALOG(LOG_WARN, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

/*
 * Simplified macro to send an error log message using the current LOG_TAG.
 */
#ifndef ALOGE
#define ALOGE(...) ((void)ALOG(LOG_ERROR, LOG_TAG, __VA_ARGS__))
#endif

#ifndef ALOGE_IF
#define ALOGE_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)ALOG(LOG_ERROR, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

/* --------------------------------------------------------------------- */

/*
 * Conditional based on whether the current LOG_TAG is enabled at
 * verbose priority.
 */
#ifndef IF_ALOGV
#if LOG_NDEBUG
#define IF_ALOGV() if (false)
#else
#define IF_ALOGV() IF_ALOG(LOG_VERBOSE, LOG_TAG)
#endif
#endif

/*
 * Conditional based on whether the current LOG_TAG is enabled at
 * debug priority.
 */
#ifndef IF_ALOGD
#define IF_ALOGD() IF_ALOG(LOG_DEBUG, LOG_TAG)
#endif

/*
 * Conditional based on whether the current LOG_TAG is enabled at
 * info priority.
 */
#ifndef IF_ALOGI
#define IF_ALOGI() IF_ALOG(LOG_INFO, LOG_TAG)
#endif

/*
 * Conditional based on whether the current LOG_TAG is enabled at
 * warn priority.
 */
#ifndef IF_ALOGW
#define IF_ALOGW() IF_ALOG(LOG_WARN, LOG_TAG)
#endif

/*
 * Conditional based on whether the current LOG_TAG is enabled at
 * error priority.
 */
#ifndef IF_ALOGE
#define IF_ALOGE() IF_ALOG(LOG_ERROR, LOG_TAG)
#endif

/* --------------------------------------------------------------------- */

/*
 * Simplified macro to send a verbose system log message using current LOG_TAG.
 */
#ifndef SLOGV
#define __SLOGV(...) \
    ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__))
#if LOG_NDEBUG
#define SLOGV(...) do { if (0) { __SLOGV(__VA_ARGS__); } } while (0)
#else
#define SLOGV(...) __SLOGV(__VA_ARGS__)
#endif
#endif

#ifndef SLOGV_IF
#if LOG_NDEBUG
#define SLOGV_IF(cond, ...)   ((void)0)
#else
#define SLOGV_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif
#endif

/*
 * Simplified macro to send a debug system log message using current LOG_TAG.
 */
#ifndef SLOGD
#define SLOGD(...) \
    ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__))
#endif

#ifndef SLOGD_IF
#define SLOGD_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

/*
 * Simplified macro to send an info system log message using current LOG_TAG.
 */
#ifndef SLOGI
#define SLOGI(...) \
    ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__))
#endif

#ifndef SLOGI_IF
#define SLOGI_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

/*
 * Simplified macro to send a warning system log message using current LOG_TAG.
 */
#ifndef SLOGW
#define SLOGW(...) \
    ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__))
#endif

#ifndef SLOGW_IF
#define SLOGW_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

/*
 * Simplified macro to send an error system log message using current LOG_TAG.
 */
#ifndef SLOGE
#define SLOGE(...) \
    ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__))
#endif

#ifndef SLOGE_IF
#define SLOGE_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

#endif /* !LINT_RLOG */

/* --------------------------------------------------------------------- */

/*
 * Simplified macro to send a verbose radio log message using current LOG_TAG.
 */
#ifndef RLOGV
#define __RLOGV(...) \
    ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__))
#if LOG_NDEBUG
#define RLOGV(...) do { if (0) { __RLOGV(__VA_ARGS__); } } while (0)
#else
#define RLOGV(...) __RLOGV(__VA_ARGS__)
#endif
#endif

#ifndef RLOGV_IF
#if LOG_NDEBUG
#define RLOGV_IF(cond, ...)   ((void)0)
#else
#define RLOGV_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif
#endif

/*
 * Simplified macro to send a debug radio log message using  current LOG_TAG.
 */
#ifndef RLOGD
#define RLOGD(...) \
    ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__))
#endif

#ifndef RLOGD_IF
#define RLOGD_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

/*
 * Simplified macro to send an info radio log message using  current LOG_TAG.
 */
#ifndef RLOGI
#define RLOGI(...) \
    ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__))
#endif

#ifndef RLOGI_IF
#define RLOGI_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

/*
 * Simplified macro to send a warning radio log message using current LOG_TAG.
 */
#ifndef RLOGW
#define RLOGW(...) \
    ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__))
#endif

#ifndef RLOGW_IF
#define RLOGW_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

/*
 * Simplified macro to send an error radio log message using current LOG_TAG.
 */
#ifndef RLOGE
#define RLOGE(...) \
    ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__))
#endif

#ifndef RLOGE_IF
#define RLOGE_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

/* --------------------------------------------------------------------- */

/*
 * Log a fatal error.  If the given condition fails, this stops program
 * execution like a normal assertion, but also generating the given message.
 * It is NOT stripped from release builds.  Note that the condition test
 * is -inverted- from the normal assert() semantics.
 */
#ifndef LOG_ALWAYS_FATAL_IF
#define LOG_ALWAYS_FATAL_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)android_printAssert(#cond, LOG_TAG, ## __VA_ARGS__)) \
    : (void)0 )
#endif

#ifndef LOG_ALWAYS_FATAL
#define LOG_ALWAYS_FATAL(...) \
    ( ((void)android_printAssert(NULL, LOG_TAG, ## __VA_ARGS__)) )
#endif

/*
 * Versions of LOG_ALWAYS_FATAL_IF and LOG_ALWAYS_FATAL that
 * are stripped out of release builds.
 */
#if LOG_NDEBUG

#ifndef LOG_FATAL_IF
#define LOG_FATAL_IF(cond, ...) ((void)0)
#endif
#ifndef LOG_FATAL
#define LOG_FATAL(...) ((void)0)
#endif

#else

#ifndef LOG_FATAL_IF
#define LOG_FATAL_IF(cond, ...) LOG_ALWAYS_FATAL_IF(cond, ## __VA_ARGS__)
#endif
#ifndef LOG_FATAL
#define LOG_FATAL(...) LOG_ALWAYS_FATAL(__VA_ARGS__)
#endif

#endif

/*
 * Assertion that generates a log message when the assertion fails.
 * Stripped out of release builds.  Uses the current LOG_TAG.
 */
#ifndef ALOG_ASSERT
#define ALOG_ASSERT(cond, ...) LOG_FATAL_IF(!(cond), ## __VA_ARGS__)
#endif

/* --------------------------------------------------------------------- */

/*
 * Basic log message macro.
 *
 * Example:
 *  ALOG(LOG_WARN, NULL, "Failed with error %d", errno);
 *
 * The second argument may be NULL or "" to indicate the "global" tag.
 */
#ifndef ALOG
#define ALOG(priority, tag, ...) \
    LOG_PRI(ANDROID_##priority, tag, __VA_ARGS__)
#endif

/*
 * Log macro that allows you to specify a number for the priority.
 */
#ifndef LOG_PRI
#define LOG_PRI(priority, tag, ...) \
    android_printLog(priority, tag, __VA_ARGS__)
#endif

/*
 * Log macro that allows you to pass in a varargs ("args" is a va_list).
 */
#ifndef LOG_PRI_VA
#define LOG_PRI_VA(priority, tag, fmt, args) \
    android_vprintLog(priority, NULL, tag, fmt, args)
#endif

/*
 * Conditional given a desired logging priority and tag.
 */
#ifndef IF_ALOG
#define IF_ALOG(priority, tag) \
    if (android_testLog(ANDROID_##priority, tag))
#endif

/* --------------------------------------------------------------------- */

/*
 * Event logging.
 */

/*
 * Event log entry types.
 */
typedef enum {
    /* Special markers for android_log_list_element type */
    EVENT_TYPE_LIST_STOP = '\n', /* declare end of list  */
    EVENT_TYPE_UNKNOWN   = '?',  /* protocol error       */

    /* must match with declaration in java/android/android/util/EventLog.java */
    EVENT_TYPE_INT       = 0,    /* uint32_t */
    EVENT_TYPE_LONG      = 1,    /* uint64_t */
    EVENT_TYPE_STRING    = 2,
    EVENT_TYPE_LIST      = 3,
    EVENT_TYPE_FLOAT     = 4,
} AndroidEventLogType;
#define sizeof_AndroidEventLogType sizeof(typeof_AndroidEventLogType)
#define typeof_AndroidEventLogType unsigned char

#ifndef LOG_EVENT_INT
#define LOG_EVENT_INT(_tag, _value) {                                       \
        int intBuf = _value;                                                \
        (void) android_btWriteLog(_tag, EVENT_TYPE_INT, &intBuf,            \
            sizeof(intBuf));                                                \
    }
#endif
#ifndef LOG_EVENT_LONG
#define LOG_EVENT_LONG(_tag, _value) {                                      \
        long long longBuf = _value;                                         \
        (void) android_btWriteLog(_tag, EVENT_TYPE_LONG, &longBuf,          \
            sizeof(longBuf));                                               \
    }
#endif
#ifndef LOG_EVENT_FLOAT
#define LOG_EVENT_FLOAT(_tag, _value) {                                     \
        float floatBuf = _value;                                            \
        (void) android_btWriteLog(_tag, EVENT_TYPE_FLOAT, &floatBuf,        \
            sizeof(floatBuf));                                              \
    }
#endif
#ifndef LOG_EVENT_STRING
#define LOG_EVENT_STRING(_tag, _value)                                      \
        (void) __android_log_bswrite(_tag, _value);
#endif

typedef enum log_id {
    LOG_ID_MIN = 0,

#ifndef LINT_RLOG
    LOG_ID_MAIN = 0,
#endif
    LOG_ID_RADIO = 1,
#ifndef LINT_RLOG
    LOG_ID_EVENTS = 2,
    LOG_ID_SYSTEM = 3,
    LOG_ID_CRASH = 4,
    LOG_ID_SECURITY = 5,
    LOG_ID_KERNEL = 6, /* place last, third-parties can not use it */
#endif

    LOG_ID_MAX
} log_id_t;
#define sizeof_log_id_t sizeof(typeof_log_id_t)
#define typeof_log_id_t unsigned char

/* --------------------------------------------------------------------- */

/*
 * The userspace structure for version 1 of the logger_entry ABI.
 */
struct logger_entry {
    uint16_t    len;    /* length of the payload */
    uint16_t    __pad;  /* no matter what, we get 2 bytes of padding */
    int32_t     pid;    /* generating process's pid */
    int32_t     tid;    /* generating process's tid */
    int32_t     sec;    /* seconds since Epoch */
    int32_t     nsec;   /* nanoseconds */
#ifndef __cplusplus
    char        msg[0]; /* the entry's payload */
#endif
};

/*
 * The userspace structure for version 2 of the logger_entry ABI.
 */
struct logger_entry_v2 {
    uint16_t    len;       /* length of the payload */
    uint16_t    hdr_size;  /* sizeof(struct logger_entry_v2) */
    int32_t     pid;       /* generating process's pid */
    int32_t     tid;       /* generating process's tid */
    int32_t     sec;       /* seconds since Epoch */
    int32_t     nsec;      /* nanoseconds */
    uint32_t    euid;      /* effective UID of logger */
#ifndef __cplusplus
    char        msg[0];    /* the entry's payload */
#endif
} __attribute__((__packed__));

/*
 * The userspace structure for version 3 of the logger_entry ABI.
 */
struct logger_entry_v3 {
    uint16_t    len;       /* length of the payload */
    uint16_t    hdr_size;  /* sizeof(struct logger_entry_v3) */
    int32_t     pid;       /* generating process's pid */
    int32_t     tid;       /* generating process's tid */
    int32_t     sec;       /* seconds since Epoch */
    int32_t     nsec;      /* nanoseconds */
    uint32_t    lid;       /* log id of the payload */
#ifndef __cplusplus
    char        msg[0];    /* the entry's payload */
#endif
} __attribute__((__packed__));

/*
 * The userspace structure for version 4 of the logger_entry ABI.
 */
struct logger_entry_v4 {
    uint16_t    len;       /* length of the payload */
    uint16_t    hdr_size;  /* sizeof(struct logger_entry_v4) */
    int32_t     pid;       /* generating process's pid */
    uint32_t    tid;       /* generating process's tid */
    uint32_t    sec;       /* seconds since Epoch */
    uint32_t    nsec;      /* nanoseconds */
    uint32_t    lid;       /* log id of the payload, bottom 4 bits currently */
    uint32_t    uid;       /* generating process's uid */
#ifndef __cplusplus
    char        msg[0];    /* the entry's payload */
#endif
};

/* struct log_time is a wire-format variant of struct timespec */
#define NS_PER_SEC 1000000000ULL

#ifdef __cplusplus

/*
 * NB: we did NOT define a copy constructor. This will result in structure
 * no longer being compatible with pass-by-value which is desired
 * efficient behavior. Also, pass-by-reference breaks C/C++ ABI.
 */
struct log_time {
public:
    uint32_t tv_sec; /* good to Feb 5 2106 */
    uint32_t tv_nsec;

    static const uint32_t tv_sec_max = 0xFFFFFFFFUL;
    static const uint32_t tv_nsec_max = 999999999UL;

    log_time(const timespec &T)
    {
        tv_sec = static_cast<uint32_t>(T.tv_sec);
        tv_nsec = static_cast<uint32_t>(T.tv_nsec);
    }
    log_time(uint32_t sec, uint32_t nsec)
    {
        tv_sec = sec;
        tv_nsec = nsec;
    }
#ifdef _SYSTEM_CORE_INCLUDE_PRIVATE_ANDROID_LOGGER_H_
    static const timespec EPOCH;
#endif
    log_time()
    {
    }
#ifdef __linux__
    log_time(clockid_t id)
    {
        timespec T;
        clock_gettime(id, &T);
        tv_sec = static_cast<uint32_t>(T.tv_sec);
        tv_nsec = static_cast<uint32_t>(T.tv_nsec);
    }
#endif
    log_time(const char *T)
    {
        const uint8_t *c = reinterpret_cast<const uint8_t*>(T);
        tv_sec = c[0] |
                 (static_cast<uint32_t>(c[1]) << 8) |
                 (static_cast<uint32_t>(c[2]) << 16) |
                 (static_cast<uint32_t>(c[3]) << 24);
        tv_nsec = c[4] |
                  (static_cast<uint32_t>(c[5]) << 8) |
                  (static_cast<uint32_t>(c[6]) << 16) |
                  (static_cast<uint32_t>(c[7]) << 24);
    }

    /* timespec */
    bool operator== (const timespec &T) const
    {
        return (tv_sec == static_cast<uint32_t>(T.tv_sec))
            && (tv_nsec == static_cast<uint32_t>(T.tv_nsec));
    }
    bool operator!= (const timespec &T) const
    {
        return !(*this == T);
    }
    bool operator< (const timespec &T) const
    {
        return (tv_sec < static_cast<uint32_t>(T.tv_sec))
            || ((tv_sec == static_cast<uint32_t>(T.tv_sec))
                && (tv_nsec < static_cast<uint32_t>(T.tv_nsec)));
    }
    bool operator>= (const timespec &T) const
    {
        return !(*this < T);
    }
    bool operator> (const timespec &T) const
    {
        return (tv_sec > static_cast<uint32_t>(T.tv_sec))
            || ((tv_sec == static_cast<uint32_t>(T.tv_sec))
                && (tv_nsec > static_cast<uint32_t>(T.tv_nsec)));
    }
    bool operator<= (const timespec &T) const
    {
        return !(*this > T);
    }

#ifdef _SYSTEM_CORE_INCLUDE_PRIVATE_ANDROID_LOGGER_H_
    log_time operator-= (const timespec &T);
    log_time operator- (const timespec &T) const
    {
        log_time local(*this);
        return local -= T;
    }
    log_time operator+= (const timespec &T);
    log_time operator+ (const timespec &T) const
    {
        log_time local(*this);
        return local += T;
    }
#endif

    /* log_time */
    bool operator== (const log_time &T) const
    {
        return (tv_sec == T.tv_sec) && (tv_nsec == T.tv_nsec);
    }
    bool operator!= (const log_time &T) const
    {
        return !(*this == T);
    }
    bool operator< (const log_time &T) const
    {
        return (tv_sec < T.tv_sec)
            || ((tv_sec == T.tv_sec) && (tv_nsec < T.tv_nsec));
    }
    bool operator>= (const log_time &T) const
    {
        return !(*this < T);
    }
    bool operator> (const log_time &T) const
    {
        return (tv_sec > T.tv_sec)
            || ((tv_sec == T.tv_sec) && (tv_nsec > T.tv_nsec));
    }
    bool operator<= (const log_time &T) const
    {
        return !(*this > T);
    }

#ifdef _SYSTEM_CORE_INCLUDE_PRIVATE_ANDROID_LOGGER_H_
    log_time operator-= (const log_time &T);
    log_time operator- (const log_time &T) const
    {
        log_time local(*this);
        return local -= T;
    }
    log_time operator+= (const log_time &T);
    log_time operator+ (const log_time &T) const
    {
        log_time local(*this);
        return local += T;
    }
#endif

    uint64_t nsec() const
    {
        return static_cast<uint64_t>(tv_sec) * NS_PER_SEC + tv_nsec;
    }

#ifdef _SYSTEM_CORE_INCLUDE_PRIVATE_ANDROID_LOGGER_H_
    static const char default_format[];

    /* Add %#q for the fraction of a second to the standard library functions */
    char *strptime(const char *s, const char *format = default_format);
#endif
} __attribute__((__packed__));

#else

typedef struct log_time {
    uint32_t tv_sec;
    uint32_t tv_nsec;
} __attribute__((__packed__)) log_time;

#endif

/*
 * The maximum size of the log entry payload that can be
 * written to the logger. An attempt to write more than
 * this amount will result in a truncated log entry.
 */
#define LOGGER_ENTRY_MAX_PAYLOAD 4068

/*
 * The maximum size of a log entry which can be read from the
 * kernel logger driver. An attempt to read less than this amount
 * may result in read() returning EINVAL.
 */
#define LOGGER_ENTRY_MAX_LEN    (5*1024)

struct log_msg {
    union {
        unsigned char buf[LOGGER_ENTRY_MAX_LEN + 1];
        struct logger_entry_v4 entry;
        struct logger_entry_v4 entry_v4;
        struct logger_entry_v3 entry_v3;
        struct logger_entry_v2 entry_v2;
        struct logger_entry    entry_v1;
    } __attribute__((aligned(4)));
#ifdef __cplusplus
    /* Matching log_time operators */
    bool operator== (const log_msg &T) const
    {
        return (entry.sec == T.entry.sec) && (entry.nsec == T.entry.nsec);
    }
    bool operator!= (const log_msg &T) const
    {
        return !(*this == T);
    }
    bool operator< (const log_msg &T) const
    {
        return (entry.sec < T.entry.sec)
            || ((entry.sec == T.entry.sec)
             && (entry.nsec < T.entry.nsec));
    }
    bool operator>= (const log_msg &T) const
    {
        return !(*this < T);
    }
    bool operator> (const log_msg &T) const
    {
        return (entry.sec > T.entry.sec)
            || ((entry.sec == T.entry.sec)
             && (entry.nsec > T.entry.nsec));
    }
    bool operator<= (const log_msg &T) const
    {
        return !(*this > T);
    }
    uint64_t nsec() const
    {
        return static_cast<uint64_t>(entry.sec) * NS_PER_SEC + entry.nsec;
    }

    /* packet methods */
    log_id_t id()
    {
        return static_cast<log_id_t>(entry.lid);
    }
    char *msg()
    {
        unsigned short hdr_size = entry.hdr_size;
        if (!hdr_size) {
            hdr_size = sizeof(entry_v1);
        }
        if ((hdr_size < sizeof(entry_v1)) || (hdr_size > sizeof(entry))) {
            return NULL;
        }
        return reinterpret_cast<char*>(buf) + hdr_size;
    }
    unsigned int len()
    {
        return (entry.hdr_size ? entry.hdr_size : sizeof(entry_v1)) + entry.len;
    }
#endif
};

struct logger;

log_id_t android_logger_get_id(struct logger *logger);

int android_logger_clear(struct logger *logger);
long android_logger_get_log_size(struct logger *logger);
int android_logger_set_log_size(struct logger *logger, unsigned long size);
long android_logger_get_log_readable_size(struct logger *logger);
int android_logger_get_log_version(struct logger *logger);

struct logger_list;

ssize_t android_logger_get_statistics(struct logger_list *logger_list,
                                      char *buf, size_t len);
ssize_t android_logger_get_prune_list(struct logger_list *logger_list,
                                      char *buf, size_t len);
int android_logger_set_prune_list(struct logger_list *logger_list,
                                  char *buf, size_t len);

#define ANDROID_LOG_RDONLY   O_RDONLY
#define ANDROID_LOG_WRONLY   O_WRONLY
#define ANDROID_LOG_RDWR     O_RDWR
#define ANDROID_LOG_ACCMODE  O_ACCMODE
#define ANDROID_LOG_NONBLOCK O_NONBLOCK
#define ANDROID_LOG_WRAP     0x40000000 /* Block until buffer about to wrap */
#define ANDROID_LOG_WRAP_DEFAULT_TIMEOUT 7200 /* 2 hour default */
#define ANDROID_LOG_PSTORE   0x80000000

struct logger_list *android_logger_list_alloc(int mode,
                                              unsigned int tail,
                                              pid_t pid);
struct logger_list *android_logger_list_alloc_time(int mode,
                                                   log_time start,
                                                   pid_t pid);
void android_logger_list_free(struct logger_list *logger_list);
/* In the purest sense, the following two are orthogonal interfaces */
int android_logger_list_read(struct logger_list *logger_list,
                             struct log_msg *log_msg);

/* Multiple log_id_t opens */
struct logger *android_logger_open(struct logger_list *logger_list,
                                   log_id_t id);
#define android_logger_close android_logger_free
/* Single log_id_t open */
struct logger_list *android_logger_list_open(log_id_t id,
                                             int mode,
                                             unsigned int tail,
                                             pid_t pid);
#define android_logger_list_close android_logger_list_free

#ifdef __linux__
clockid_t android_log_clockid();
#endif

/*
 * log_id_t helpers
 */
log_id_t android_name_to_log_id(const char *logName);
const char *android_log_id_to_name(log_id_t log_id);

/* For manipulating lists of events. */

#define ANDROID_MAX_LIST_NEST_DEPTH 8

/*
 * The opaque context used to manipulate lists of events.
 */
typedef struct android_log_context_internal *android_log_context;

/*
 * Elements returned when reading a list of events.
 */
typedef struct {
    AndroidEventLogType type;
    uint16_t complete;
    uint16_t len;
    union {
        int32_t int32;
        int64_t int64;
        char *string;
        float float32;
    } data;
} android_log_list_element;

/*
 * Creates a context associated with an event tag to write elements to
 * the list of events.
 */
android_log_context create_android_logger(uint32_t tag);

/* All lists must be braced by a begin and end call */
/*
 * NB: If the first level braces are missing when specifying multiple
 *     elements, we will manufacturer a list to embrace it for your API
 *     convenience. For a single element, it will remain solitary.
 */
int android_log_write_list_begin(android_log_context ctx);
int android_log_write_list_end(android_log_context ctx);

int android_log_write_int32(android_log_context ctx, int32_t value);
int android_log_write_int64(android_log_context ctx, int64_t value);
int android_log_write_string8(android_log_context ctx, const char *value);
int android_log_write_string8_len(android_log_context ctx,
                                  const char *value, size_t maxlen);
int android_log_write_float32(android_log_context ctx, float value);

/* Submit the composed list context to the specified logger id */
/* NB: LOG_ID_EVENTS and LOG_ID_SECURITY only valid binary buffers */
int android_log_write_list(android_log_context ctx, log_id_t id);

/*
 * Creates a context from a raw buffer representing a list of events to be read.
 */
android_log_context create_android_log_parser(const char *msg, size_t len);

android_log_list_element android_log_read_next(android_log_context ctx);
android_log_list_element android_log_peek_next(android_log_context ctx);

/* Finished with reader or writer context */
int android_log_destroy(android_log_context *ctx);

#ifdef __cplusplus
/* android_log_context C++ helpers */
class android_log_event_context {
    android_log_context ctx;
    int ret;

public:
    explicit android_log_event_context(int tag) : ret(0) {
        ctx = create_android_logger(static_cast<uint32_t>(tag));
    }
    explicit android_log_event_context(log_msg& log_msg) : ret(0) {
        ctx = create_android_log_parser(log_msg.msg() + sizeof(uint32_t),
                                        log_msg.entry.len - sizeof(uint32_t));
    }
    ~android_log_event_context() { android_log_destroy(&ctx); }

    int close() {
        int retval = android_log_destroy(&ctx);
        if (retval < 0) ret = retval;
        return retval;
    }

    /* To allow above C calls to use this class as parameter */
    operator android_log_context() const { return ctx; }

    int status() const { return ret; }

    int begin() {
        int retval = android_log_write_list_begin(ctx);
        if (retval < 0) ret = retval;
        return ret;
    }
    int end() {
        int retval = android_log_write_list_end(ctx);
        if (retval < 0) ret = retval;
        return ret;
    }

    android_log_event_context& operator <<(int32_t value) {
        int retval = android_log_write_int32(ctx, value);
        if (retval < 0) ret = retval;
        return *this;
    }
    android_log_event_context& operator <<(uint32_t value) {
        int retval = android_log_write_int32(ctx, static_cast<int32_t>(value));
        if (retval < 0) ret = retval;
        return *this;
    }
    android_log_event_context& operator <<(int64_t value) {
        int retval = android_log_write_int64(ctx, value);
        if (retval < 0) ret = retval;
        return *this;
    }
    android_log_event_context& operator <<(uint64_t value) {
        int retval = android_log_write_int64(ctx, static_cast<int64_t>(value));
        if (retval < 0) ret = retval;
        return *this;
    }
    android_log_event_context& operator <<(const char* value) {
        int retval = android_log_write_string8(ctx, value);
        if (retval < 0) ret = retval;
        return *this;
    }
    android_log_event_context& operator <<(std::string& value) {
        int retval = android_log_write_string8_len(ctx,
                                                   value.data(),
                                                   value.length());
        if (retval < 0) ret = retval;
        return *this;
    }
    android_log_event_context& operator <<(float value) {
        int retval = android_log_write_float32(ctx, value);
        if (retval < 0) ret = retval;
        return *this;
    }

    int write(log_id_t id) {
        int retval = android_log_write_list(ctx, id);
        if (retval < 0) ret = retval;
        return ret;
    }

    android_log_list_element read() { return android_log_read_next(ctx); }
    android_log_list_element peek() { return android_log_peek_next(ctx); }

};
#endif

/* --------------------------------------------------------------------- */

/*
 * The stuff in the rest of this file should not be used directly.
 */

#define android_printLog(prio, tag, ...) \
    __android_log_print(prio, tag, __VA_ARGS__)

#define android_vprintLog(prio, cond, tag, ...) \
    __android_log_vprint(prio, tag, __VA_ARGS__)

/* XXX Macros to work around syntax errors in places where format string
 * arg is not passed to ALOG_ASSERT, LOG_ALWAYS_FATAL or LOG_ALWAYS_FATAL_IF
 * (happens only in debug builds).
 */

/* Returns 2nd arg.  Used to substitute default value if caller's vararg list
 * is empty.
 */
#define __android_second(dummy, second, ...)     second

/* If passed multiple args, returns ',' followed by all but 1st arg, otherwise
 * returns nothing.
 */
#define __android_rest(first, ...)               , ## __VA_ARGS__

#define android_printAssert(cond, tag, ...) \
    __android_log_assert(cond, tag, \
        __android_second(0, ## __VA_ARGS__, NULL) __android_rest(__VA_ARGS__))

#define android_writeLog(prio, tag, text) \
    __android_log_write(prio, tag, text)

#define android_bWriteLog(tag, payload, len) \
    __android_log_bwrite(tag, payload, len)
#define android_btWriteLog(tag, type, payload, len) \
    __android_log_btwrite(tag, type, payload, len)

#define android_errorWriteLog(tag, subTag) \
    __android_log_error_write(tag, subTag, -1, NULL, 0)

#define android_errorWriteWithInfoLog(tag, subTag, uid, data, dataLen) \
    __android_log_error_write(tag, subTag, uid, data, dataLen)

/*
 *    IF_ALOG uses android_testLog, but IF_ALOG can be overridden.
 *    android_testLog will remain constant in its purpose as a wrapper
 *        for Android logging filter policy, and can be subject to
 *        change. It can be reused by the developers that override
 *        IF_ALOG as a convenient means to reimplement their policy
 *        over Android.
 */
#if LOG_NDEBUG /* Production */
#define android_testLog(prio, tag) \
    (__android_log_is_loggable_len(prio, tag, (tag && *tag) ? strlen(tag) : 0, \
                                   ANDROID_LOG_DEBUG) != 0)
#else
#define android_testLog(prio, tag) \
    (__android_log_is_loggable_len(prio, tag, (tag && *tag) ? strlen(tag) : 0, \
                                   ANDROID_LOG_VERBOSE) != 0)
#endif

/*
 * Use the per-tag properties "log.tag.<tagname>" to generate a runtime
 * result of non-zero to expose a log. prio is ANDROID_LOG_VERBOSE to
 * ANDROID_LOG_FATAL. default_prio if no property. Undefined behavior if
 * any other value.
 */
int __android_log_is_loggable(int prio, const char *tag, int default_prio);
int __android_log_is_loggable_len(int prio, const char *tag, size_t len, int default_prio);

int __android_log_security(); /* Device Owner is present */

int __android_log_error_write(int tag, const char *subTag, int32_t uid,
                              const char *data, uint32_t dataLen);

/*
 * Send a simple string to the log.
 */
int __android_log_buf_write(int bufID, int prio, const char *tag, const char *text);
int __android_log_buf_print(int bufID, int prio, const char *tag, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((__format__(printf, 4, 5)))
#endif
    ;

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#ifdef __cplusplus
}
#endif

#endif /* _ANDROID_LOG_H */

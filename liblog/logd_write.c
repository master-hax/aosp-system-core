/*
 * Copyright (C) 2007-2014 The Android Open Source Project
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
#if !defined(_WIN32)
#include <pthread.h>
#include <semaphore.h>
#include <sys/prctl.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#if (FAKE_LOG_DEVICE == 0)
#include <sys/socket.h>
#include <sys/un.h>
#endif
#include <time.h>
#include <unistd.h>

#ifdef __BIONIC__
#include <android/set_abort_message.h>
#endif

#include <log/logd.h>
#include <log/logger.h>
#include <log/log_read.h>
#include <private/android_filesystem_config.h>
#include <private/android_logger.h>

#define LOG_BUF_SIZE 1024

#if FAKE_LOG_DEVICE
/* This will be defined when building for the host. */
#include "fake_log_device.h"
#endif

static int __write_to_log_init(log_id_t, struct iovec *vec, size_t nr);
static int (*write_to_log)(log_id_t, struct iovec *vec, size_t nr) = __write_to_log_init;
#if !defined(_WIN32)
static pthread_mutex_t log_init_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

#ifndef __unused
#define __unused  __attribute__((__unused__))
#endif

#if FAKE_LOG_DEVICE
static int log_fds[(int)LOG_ID_MAX] = { -1, -1, -1, -1, -1 };
#else
static int logd_fd = -1;
static int pstore_fd = -1;
#endif

/*
 * This is used by the C++ code to decide if it should write logs through
 * the C code.  Basically, if /dev/socket/logd is available, we're running in
 * the simulator rather than a desktop tool and want to use the device.
 */
static enum {
    kLogUninitialized, kLogNotAvailable, kLogAvailable
} g_log_status = kLogUninitialized;

int __android_log_dev_available(void)
{
    if (g_log_status == kLogUninitialized) {
        if (access("/dev/socket/logdw", W_OK) == 0)
            g_log_status = kLogAvailable;
        else
            g_log_status = kLogNotAvailable;
    }

    return (g_log_status == kLogAvailable);
}

#if !FAKE_LOG_DEVICE
/* give up, resources too limited */
static int __write_to_log_null(log_id_t log_fd __unused, struct iovec *vec __unused,
                               size_t nr __unused)
{
    return -1;
}
#endif

/* log_init_lock assumed */
static int __write_to_log_initialize()
{
    int i, ret = 0;

#if FAKE_LOG_DEVICE
    for (i = 0; i < LOG_ID_MAX; i++) {
        char buf[sizeof("/dev/log_system")];
        snprintf(buf, sizeof(buf), "/dev/log_%s", android_log_id_to_name(i));
        log_fds[i] = fakeLogOpen(buf, O_WRONLY);
    }
#else
    if (logd_fd >= 0) {
        i = logd_fd;
        logd_fd = -1;
        close(i);
    }
    if (pstore_fd >= 0) {
        i = pstore_fd;
        pstore_fd = -1;
        close(i);
    }
    pstore_fd = open("/dev/pmsg0", O_WRONLY);

    i = socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (i < 0) {
        ret = -errno;
        write_to_log = __write_to_log_null;
    } else if (fcntl(i, F_SETFL, O_NONBLOCK) < 0) {
        ret = -errno;
        close(i);
        i = -1;
        write_to_log = __write_to_log_null;
    } else {
        struct sockaddr_un un;
        memset(&un, 0, sizeof(struct sockaddr_un));
        un.sun_family = AF_UNIX;
        strcpy(un.sun_path, "/dev/socket/logdw");

        if (connect(i, (struct sockaddr *)&un, sizeof(struct sockaddr_un)) < 0) {
            ret = -errno;
            close(i);
            i = -1;
        }
    }
    logd_fd = i;
#endif

    return ret;
}

static uid_t last_uid = AID_ROOT; /* logd *always* starts up as AID_ROOT */
static pid_t last_pid = (pid_t) -1;

static int __write_to_log_kernel(log_id_t log_id, struct iovec *vec, size_t nr)
{
    ssize_t ret;
#if FAKE_LOG_DEVICE
    int log_fd;

    if (/*(int)log_id >= 0 &&*/ (int)log_id < (int)LOG_ID_MAX) {
        log_fd = log_fds[(int)log_id];
    } else {
        return -EBADF;
    }
    do {
        ret = fakeLogWritev(log_fd, vec, nr);
        if (ret < 0) {
            ret = -errno;
        }
    } while (ret == -EINTR);
#else
    static const unsigned header_length = 2;
    struct iovec newVec[nr + header_length];
    android_log_header_t header;
    android_pmsg_log_header_t pmsg_header;
    struct timespec ts;
    size_t i, payload_size;

    if (last_uid == AID_ROOT) { /* have we called to get the UID yet? */
        last_uid = getuid();
    }
    if (last_pid == (pid_t) -1) {
        last_pid = getpid();
    }
    /*
     *  struct {
     *      // whate we provire to pstore
     *      android_pmsg_log_header_t pmsg_header;
     *      // what we provide to socket
     *      android_log_header_t header;
     *      // caller provides
     *      union {
     *          struct {
     *              char     prio;
     *              char     payload[];
     *          } string;
     *          struct {
     *              uint32_t tag
     *              char     payload[];
     *          } binary;
     *      };
     *  };
     */

    clock_gettime(CLOCK_REALTIME, &ts);

    pmsg_header.magic = LOGGER_MAGIC;
    pmsg_header.len = sizeof(pmsg_header) + sizeof(header);
    pmsg_header.uid = last_uid;
    pmsg_header.pid = last_pid;

    header.id = log_id;
    header.tid = gettid();
    header.realtime.tv_sec = ts.tv_sec;
    header.realtime.tv_nsec = ts.tv_nsec;

    newVec[0].iov_base   = (unsigned char *) &pmsg_header;
    newVec[0].iov_len    = sizeof(pmsg_header);
    newVec[1].iov_base   = (unsigned char *) &header;
    newVec[1].iov_len    = sizeof(header);

    for (payload_size = 0, i = header_length; i < nr + header_length; i++) {
        newVec[i].iov_base = vec[i - header_length].iov_base;
        payload_size += newVec[i].iov_len = vec[i - header_length].iov_len;

        if (payload_size > LOGGER_ENTRY_MAX_PAYLOAD) {
            newVec[i].iov_len -= payload_size - LOGGER_ENTRY_MAX_PAYLOAD;
            if (newVec[i].iov_len) {
                ++i;
            }
            payload_size = LOGGER_ENTRY_MAX_PAYLOAD;
            break;
        }
    }
    pmsg_header.len += payload_size;

    if (pstore_fd >= 0) {
        TEMP_FAILURE_RETRY(writev(pstore_fd, newVec, i));
    }

    if (last_uid == AID_LOGD) { /* logd, after initialization and priv drop */
        /*
         * ignore log messages we send to ourself (logd).
         * Such log messages are often generated by libraries we depend on
         * which use standard Android logging.
         */
        return 0;
    }

    if (logd_fd < 0) {
        return -EBADF;
    }

    /*
     * The write below could be lost, but will never block.
     *
     * To logd, we drop the pmsg_header
     *
     * ENOTCONN occurs if logd dies.
     * EAGAIN occurs if logd is overloaded.
     */
    ret = TEMP_FAILURE_RETRY(writev(logd_fd, newVec + 1, i - 1));
    if (ret < 0) {
        ret = -errno;
        if (ret == -ENOTCONN) {
#if !defined(_WIN32)
            pthread_mutex_lock(&log_init_lock);
#endif
            ret = __write_to_log_initialize();
#if !defined(_WIN32)
            pthread_mutex_unlock(&log_init_lock);
#endif

            if (ret < 0) {
                return ret;
            }

            ret = TEMP_FAILURE_RETRY(writev(logd_fd, newVec + 1, i - 1));
            if (ret < 0) {
                ret = -errno;
            }
        }
    }

    if (ret > (ssize_t)sizeof(header)) {
        ret -= sizeof(header);
    }
#endif

    return ret;
}

#if FAKE_LOG_DEVICE
static const char *LOG_NAME[LOG_ID_MAX] = {
    [LOG_ID_MAIN] = "main",
    [LOG_ID_RADIO] = "radio",
    [LOG_ID_EVENTS] = "events",
    [LOG_ID_SYSTEM] = "system",
    [LOG_ID_CRASH] = "crash"
};

const char *android_log_id_to_name(log_id_t log_id)
{
    if (log_id >= LOG_ID_MAX) {
        log_id = LOG_ID_MAIN;
    }
    return LOG_NAME[log_id];
}
#endif

static int __write_to_log_init(log_id_t log_id, struct iovec *vec, size_t nr)
{
#if !defined(_WIN32)
    pthread_mutex_lock(&log_init_lock);
#endif

    if (write_to_log == __write_to_log_init) {
        int ret;

        ret = __write_to_log_initialize();
        if (ret < 0) {
#if !defined(_WIN32)
            pthread_mutex_unlock(&log_init_lock);
#endif
            return ret;
        }

        write_to_log = __write_to_log_kernel;
    }

#if !defined(_WIN32)
    pthread_mutex_unlock(&log_init_lock);
#endif

    return write_to_log(log_id, vec, nr);
}

int __android_log_write(int prio, const char *tag, const char *msg)
{
    struct iovec vec[3];
    log_id_t log_id = LOG_ID_MAIN;
    char tmp_tag[32];

    if (!tag)
        tag = "";

    /* XXX: This needs to go! */
    if (!strcmp(tag, "HTC_RIL") ||
        !strncmp(tag, "RIL", 3) || /* Any log tag with "RIL" as the prefix */
        !strncmp(tag, "IMS", 3) || /* Any log tag with "IMS" as the prefix */
        !strcmp(tag, "AT") ||
        !strcmp(tag, "GSM") ||
        !strcmp(tag, "STK") ||
        !strcmp(tag, "CDMA") ||
        !strcmp(tag, "PHONE") ||
        !strcmp(tag, "SMS")) {
            log_id = LOG_ID_RADIO;
            /* Inform third party apps/ril/radio.. to use Rlog or RLOG */
            snprintf(tmp_tag, sizeof(tmp_tag), "use-Rlog/RLOG-%s", tag);
            tag = tmp_tag;
    }

#if __BIONIC__
    if (prio == ANDROID_LOG_FATAL) {
        android_set_abort_message(msg);
    }
#endif

    vec[0].iov_base   = (unsigned char *) &prio;
    vec[0].iov_len    = 1;
    vec[1].iov_base   = (void *) tag;
    vec[1].iov_len    = strlen(tag) + 1;
    vec[2].iov_base   = (void *) msg;
    vec[2].iov_len    = strlen(msg) + 1;

    return write_to_log(log_id, vec, 3);
}

int __android_log_buf_write(int bufID, int prio, const char *tag, const char *msg)
{
    struct iovec vec[3];
    char tmp_tag[32];

    if (!tag)
        tag = "";

    /* XXX: This needs to go! */
    if ((bufID != LOG_ID_RADIO) &&
         (!strcmp(tag, "HTC_RIL") ||
        !strncmp(tag, "RIL", 3) || /* Any log tag with "RIL" as the prefix */
        !strncmp(tag, "IMS", 3) || /* Any log tag with "IMS" as the prefix */
        !strcmp(tag, "AT") ||
        !strcmp(tag, "GSM") ||
        !strcmp(tag, "STK") ||
        !strcmp(tag, "CDMA") ||
        !strcmp(tag, "PHONE") ||
        !strcmp(tag, "SMS"))) {
            bufID = LOG_ID_RADIO;
            /* Inform third party apps/ril/radio.. to use Rlog or RLOG */
            snprintf(tmp_tag, sizeof(tmp_tag), "use-Rlog/RLOG-%s", tag);
            tag = tmp_tag;
    }

    vec[0].iov_base   = (unsigned char *) &prio;
    vec[0].iov_len    = 1;
    vec[1].iov_base   = (void *) tag;
    vec[1].iov_len    = strlen(tag) + 1;
    vec[2].iov_base   = (void *) msg;
    vec[2].iov_len    = strlen(msg) + 1;

    return write_to_log(bufID, vec, 3);
}

int __android_log_vprint(int prio, const char *tag, const char *fmt, va_list ap)
{
    char buf[LOG_BUF_SIZE];

    vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);

    return __android_log_write(prio, tag, buf);
}

int __android_log_print(int prio, const char *tag, const char *fmt, ...)
{
    va_list ap;
    char buf[LOG_BUF_SIZE];

    va_start(ap, fmt);
    vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
    va_end(ap);

    return __android_log_write(prio, tag, buf);
}

int __android_log_buf_print(int bufID, int prio, const char *tag, const char *fmt, ...)
{
    va_list ap;
    char buf[LOG_BUF_SIZE];

    va_start(ap, fmt);
    vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
    va_end(ap);

    return __android_log_buf_write(bufID, prio, tag, buf);
}

void __android_log_assert(const char *cond, const char *tag,
                          const char *fmt, ...)
{
    char buf[LOG_BUF_SIZE];

    if (fmt) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
        va_end(ap);
    } else {
        /* Msg not provided, log condition.  N.B. Do not use cond directly as
         * format string as it could contain spurious '%' syntax (e.g.
         * "%d" in "blocks%devs == 0").
         */
        if (cond)
            snprintf(buf, LOG_BUF_SIZE, "Assertion failed: %s", cond);
        else
            strcpy(buf, "Unspecified assertion failed");
    }

    __android_log_write(ANDROID_LOG_FATAL, tag, buf);
    __builtin_trap(); /* trap so we have a chance to debug the situation */
    /* NOTREACHED */
}

int __android_log_bwrite(int32_t tag, const void *payload, size_t len)
{
    struct iovec vec[2];

    vec[0].iov_base = &tag;
    vec[0].iov_len = sizeof(tag);
    vec[1].iov_base = (void*)payload;
    vec[1].iov_len = len;

    return write_to_log(LOG_ID_EVENTS, vec, 2);
}

/*
 * Like __android_log_bwrite, but takes the type as well.  Doesn't work
 * for the general case where we're generating lists of stuff, but very
 * handy if we just want to dump an integer into the log.
 */
int __android_log_btwrite(int32_t tag, char type, const void *payload,
                          size_t len)
{
    struct iovec vec[3];

    vec[0].iov_base = &tag;
    vec[0].iov_len = sizeof(tag);
    vec[1].iov_base = &type;
    vec[1].iov_len = sizeof(type);
    vec[2].iov_base = (void*)payload;
    vec[2].iov_len = len;

    return write_to_log(LOG_ID_EVENTS, vec, 3);
}

/*
 * Like __android_log_bwrite, but used for writing strings to the
 * event log.
 */
int __android_log_bswrite(int32_t tag, const char *payload)
{
    struct iovec vec[4];
    char type = EVENT_TYPE_STRING;
    uint32_t len = strlen(payload);

    vec[0].iov_base = &tag;
    vec[0].iov_len = sizeof(tag);
    vec[1].iov_base = &type;
    vec[1].iov_len = sizeof(type);
    vec[2].iov_base = &len;
    vec[2].iov_len = sizeof(len);
    vec[3].iov_base = (void*)payload;
    vec[3].iov_len = len;

    return write_to_log(LOG_ID_EVENTS, vec, 4);
}

#if !defined(_WIN32)
#if !FAKE_LOG_DEVICE

/* Producer-Consumer Log Writing */

typedef struct __attribute__((__packed__)) {
    android_log_header_t log_header;
    uint16_t payload_length;
    unsigned char payload[(4*1024) - sizeof(uint16_t) - sizeof(android_log_header_t)];
} entry_t;

#define PC_NUM_ENTRIES 16

typedef struct {
    pthread_t thread;
    sem_t full;
    sem_t empty;
    sem_t write;
    uint16_t size;
    uint16_t producer;
    uint16_t consumer;
    uint8_t started;
    uint8_t stopped;
    entry_t entries[PC_NUM_ENTRIES];
} buffer_t;

static buffer_t *__android_pc_buffer;

/* Consumer */
static void * __android_pc_thread_start(void *obj __unused)
{
    if (!__android_pc_buffer) {
        return NULL;
    }

    if ((pstore_fd < 0) || (logd_fd < 0)) {
        pthread_mutex_lock(&log_init_lock);
        __write_to_log_initialize();
        pthread_mutex_unlock(&log_init_lock);
    }

    if ((pstore_fd < 0) || (logd_fd < 0)) {
        __android_pc_buffer->started = 0;
        __android_pc_buffer->stopped = 1;
        return NULL;
    }

    prctl(PR_SET_NAME, "logd.writer.per");

    if (last_uid == AID_ROOT) { /* have we called to get the UID yet? */
        last_uid = getuid();
    }
    if (last_pid == (pid_t) -1) {
        last_pid = getpid();
    }

    while (__android_pc_buffer && !(__android_pc_buffer->started
            ? sem_wait(&__android_pc_buffer->full)
            : sem_trywait(&__android_pc_buffer->full))) {
        uint16_t consumer_before, consumer_after;
        entry_t *e;
        static const size_t num_vec = 3;
        struct iovec vec[num_vec];
        android_pmsg_log_header_t pmsg_header;

        if (!__android_pc_buffer
                || (!__android_pc_buffer->started
                    && (__android_pc_buffer->consumer
                        == __android_pc_buffer->producer))) {
            break;
        }

        consumer_before = __android_pc_buffer->consumer;
        consumer_after = (consumer_before + 1) % __android_pc_buffer->size;

        e = &__android_pc_buffer->entries[consumer_before];

        pmsg_header.magic = LOGGER_MAGIC;
        pmsg_header.len = sizeof(pmsg_header) + sizeof(e->log_header)
                        + e->payload_length;
        pmsg_header.uid = last_uid;
        pmsg_header.pid = last_pid;

        vec[0].iov_base = (unsigned char *) &pmsg_header;
        vec[0].iov_len  = sizeof(pmsg_header);
        vec[1].iov_base = (unsigned char *) &e->log_header;
        vec[1].iov_len  = sizeof(e->log_header);
        vec[2].iov_base = e->payload;
        vec[2].iov_len  = e->payload_length;

        if (pstore_fd >= 0) {
            TEMP_FAILURE_RETRY(writev(pstore_fd, vec, num_vec));
        }

        if (logd_fd >= 0) {
            ssize_t ret = -EAGAIN;
            while (ret == -EAGAIN) {
                ret = TEMP_FAILURE_RETRY(writev(logd_fd, vec + 1, num_vec - 1));
                if (ret < 0) {
                    ret = -errno;
                }
                if (ret == -ENOTCONN) {
                    pthread_mutex_lock(&log_init_lock);
                    ret = __write_to_log_initialize();
                    pthread_mutex_unlock(&log_init_lock);

                    if (ret >= 0) {
                        ret = -EAGAIN;
                    }
                }
            }
        }

        __android_pc_buffer->consumer = consumer_after;
        sem_post(&__android_pc_buffer->empty);
    }

    if (__android_pc_buffer) {
        __android_pc_buffer->started = 0;
        __android_pc_buffer->stopped = 1;
    }
    return NULL;
}

/* Producer(s) */
static int __write_to_log_pc(log_id_t log_id, struct iovec *vec, size_t nr)
{
    struct timespec ts;
    unsigned producer_before, producer_after;
    entry_t *e;
    unsigned char *p;
    size_t left;

    if (!__android_pc_buffer) {
        __android_pc_buffer = calloc((size_t)1, sizeof(buffer_t));
        if (!__android_pc_buffer) {
            return -ENOMEM;
        }
        __android_pc_buffer->size = PC_NUM_ENTRIES;
        sem_init(&__android_pc_buffer->empty, 0, __android_pc_buffer->size);
        sem_init(&__android_pc_buffer->full, 0, 0);
        sem_init(&__android_pc_buffer->write, 0, 1);
    }

    if (sem_trywait(&__android_pc_buffer->empty)) {
        return -EAGAIN;
    }

    sem_wait(&__android_pc_buffer->write);
    producer_before = __android_pc_buffer->producer;
    producer_after = (producer_before + 1) % __android_pc_buffer->size;

    clock_gettime(CLOCK_REALTIME, &ts);

    e = &__android_pc_buffer->entries[producer_before];
    e->log_header.id = log_id;
    e->log_header.tid = gettid();
    e->log_header.realtime.tv_sec = ts.tv_sec;
    e->log_header.realtime.tv_nsec = ts.tv_nsec;

    p = e->payload;
    left = sizeof(e->payload);
    while (nr) {
        size_t len = vec->iov_len;
        if (len > left) {
            len = left;
            nr = 1;
        }
        memcpy(p, vec->iov_base, len);
        left -= len;
        if (left == 0) {
            break;
        }
        ++vec;
        p += len;
        --nr;
    }
    e->payload_length = sizeof(e->payload) - left;
    __android_pc_buffer->producer = producer_after;
    sem_post(&__android_pc_buffer->full);
    if (!__android_pc_buffer->started) {
        pthread_attr_t attr;

        if (!pthread_attr_init(&attr)) {
            if (!pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)
             && !pthread_create(&__android_pc_buffer->thread, &attr,
                                __android_pc_thread_start, NULL)) {
                __android_pc_buffer->started = 1;
                sem_post(&__android_pc_buffer->write);
                pthread_attr_destroy(&attr);
                return 0;
            }
            pthread_attr_destroy(&attr);
        }
        sem_post(&__android_pc_buffer->write);
        return -ENOMEM;
    }
    sem_post(&__android_pc_buffer->write);
    return 0;
}

void __android_set_to_log_pc()
{
    write_to_log = __write_to_log_pc;
}

void __android_set_to_log_direct()
{
    buffer_t *b;

    if (write_to_log != __write_to_log_pc) {
        return;
    }

    write_to_log = __write_to_log_init;

    b = __android_pc_buffer;
    if (b) {
        int i;

        b->started = 0;
        if (!sem_getvalue(&b->full, &i) && (i <= 0)) {
            sem_post(&b->full);
        }

        for (i = 10; !b->stopped && i; --i) {
            sleep(1);
        }

        __android_pc_buffer = NULL;
        free(b);
    }
}

#endif
#endif

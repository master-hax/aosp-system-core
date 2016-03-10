/*
 * Copyright (C) 2007-2016 The Android Open Source Project
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
 * pmsg write handler
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include <log/log.h>
#include <log/logger.h>

#include <private/android_logger.h>

#include "log_cdefs.h"

/*
 * Virtual pmsg filesystem
 *
 * Payload will comprise the string "<basedir>:<basefile>\0<content>" to a
 * maximum of LOGGER_ENTRY_MAX_PAYLOAD, but scaled to the last newline in the
 * file.
 *
 * Will hijack the header.realtime.tv_nsec field for a sequence number.
 */

static inline const char *strnrchr(const char *buf, size_t len, char c) {
    const char *cp = buf + len;
    while (*--cp != c) {
        if (cp <= buf) {
            return buf + len;
        }
    }
    return cp;
}

static inline ssize_t __pmsg_write(
        int fd,
        log_id_t logId,
        char prio,
        struct timespec *ts,
        const char *tag,
        const char *buf,
        size_t len,
        size_t sequence) {
    const char *cp;
    char *packet;
    android_pmsg_log_header_t *pmsg_header;
    android_log_header_t *header;
    char *payload;
    size_t tag_len, ret = len;
    ssize_t packet_len;

    if (ret >= LOGGER_ENTRY_MAX_PAYLOAD) {
        ret = LOGGER_ENTRY_MAX_PAYLOAD - 1;
    }
    cp = strnrchr(buf, ret, '\n');
    ret = cp - buf;
    if ((ret < len) && (buf[ret] == '\n')) {
        ++ret;
    }
    tag_len = strlen(tag);
    packet_len = sizeof(android_pmsg_log_header_t) +
                 sizeof(android_log_header_t) +
                 sizeof(char) +
                 tag_len + 1 +
                 ret;
    packet = (char *)calloc(1, packet_len);
    if (!packet) {
        return -ENOMEM;
    }
    pmsg_header = (android_pmsg_log_header_t *)packet;
    pmsg_header->magic = LOGGER_MAGIC;
    pmsg_header->len = packet_len;
    pmsg_header->uid = getuid();
    pmsg_header->pid = getpid();
    header = (android_log_header_t *)(pmsg_header + 1);
    header->id = logId;
    header->tid = gettid();
    header->realtime.tv_sec = ts->tv_sec;
    header->realtime.tv_nsec = sequence;
    payload = (char *)(header + 1);
    *payload++ = prio;
    strcpy(payload, tag);
    payload += tag_len + 1;
    memcpy(payload, buf, ret);

    packet_len = TEMP_FAILURE_RETRY(write(fd, packet, packet_len));
    free(packet);
    if (packet_len < 0) {
        return errno ? -errno : -EIO;
    }
    return ret;
}

/* Write a buffer as filename references (tag = <basedir>:<basename>) */
LIBLOG_ABI_PRIVATE ssize_t pmsg_write(log_id_t logId, char prio,
                                      const char *filename,
                                      const char *buf, size_t len) {
    size_t length, sequence;
    const char *tag;
    char *cp, *slash;
    int fd;
    struct timespec ts;

    clock_gettime(android_log_clockid(), &ts);

    fd = TEMP_FAILURE_RETRY(open("/dev/pmsg0", O_WRONLY));
    if (fd < 0) {
        return errno ? -errno : -EBADF;
    }

    cp = strdup(filename);
    if (!cp) {
        close(fd);
        return -ENOMEM;
    }

    tag = cp;
    slash = strrchr(cp, '/');
    if (slash) {
        *slash = ':';
        slash = strrchr(cp, '/');
        if (slash) {
            tag = slash + 1;
        }
    }

    for (sequence = 0, length = len; length; ++sequence) {
        ssize_t ret = __pmsg_write(fd, logId, prio, &ts, tag, buf, length, sequence);
        if (ret <= 0) {
            free(cp);
            close(fd);
            return ret;
        }
        length -= ret;
        buf += ret;
    }
    free(cp);
    close(fd);
    return len;
}

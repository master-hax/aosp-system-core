/*
 * Copyright 2012, Samsung Telecommunications of America
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Written by William Roberts <w.roberts@sta.samsung.com>
 */

#define LOG_TAG "audit_log"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/klog.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <cutils/log.h>

#include "libaudit.h"
#include "audit_log.h"

#define AUDIT_LOG_MODE (S_IRUSR | S_IWUSR | S_IRGRP)
#define AUDIT_LOG_FLAGS (O_RDWR | O_CREAT | O_SYNC)

struct audit_log {
	int fd;
	size_t total_bytes;
	size_t threshold;
	char *rotatefile;
	char *logfile;
};

/**
 * Wraps open with a fchmod to prevent umask issues from arising in
 * permission setting.
 * The default umask is 022, so either the umask would need to be
 * backed up and restored or just use fchmod to ensure the permissions
 * are correct.
 *
 * @param file
 *  The file to open
 * @param flags
 *  The flags passed to open
 * @param mode
 *  The mode passed to open and fchmod
 * @return
 *  The fd, or -errno on error
 */
static inline int open_log(const char *file, int flags, mode_t mode) {

    int err;
    int fd = open(file, flags, mode);
    if(fd >= 0) {
        err = fchmod(fd, mode);
        if(err < 0) {
            err = -errno;
            close(fd);
            return err;
        }
    }
    else {
        err = -errno;
        SLOGE("Could not open audit log%s: %s\n",
                file, strerror(-err));
        return err;
    }
    return fd;
}

/**
 * Writes data pointed by buf to audit log, appends a trailing newline.
 * @param l
 *  The log to write, MUST NOT BE NULL!
 * @param buf
 *  The data to write, MUST NOT BE NULL!
 * @param len
 *  The length of the data
 * @return
 *  0 on success, -error on failure
 */
static int write_log(audit_log *l, const void *buf, size_t len) {

	int rc = 0;
	ssize_t bytes = 0;

	/*
	 * Ensure that the pointer offset and number of bytes written are the same
	 * size. Avoid char *, as on future ports of Linux on various architectures,
	 * their is no guarantee that char == 1 byte. Think of the int == 32 bit
	 * issue on 64 bit machines. A hypothetical of where this could occur is on
	 * systems that are not byte addressable it could be defined as something
	 * else.
	 */
	const uint8_t *b = (uint8_t *)buf;

	do {
		bytes = write(l->fd, b, len);
		if (bytes < 0) {
			if (errno != EINTR) {
				rc = -errno;
				SLOGE("Error writing to audit log: %s, error: %s\n",
				l->logfile, strerror(rc));
				goto out;
			}
			/*
			 * If their was no forward progress made
			 * on the write due to EINTR, then keep trying.
			 */
			continue;
		}

		b += bytes;
		len -= bytes;
		l->total_bytes += bytes;
	} while (len > 0);

out:
	/*
	 * Always attempt to write a newline, but ignore
	 * any errors as it could be a cascading effect
	 * from above. On a write failure above, ^perhaps^
	 * the trailing newline write will succeed, if it
	 * does, this will result in a cleaner log file.
	 */
	bytes = write(l->fd, "\n", 1);
	l->total_bytes += (bytes > 0) ? bytes : 0;

	/*
	 * Always attempt to rotate, even in the
	 * face of errors above, if the logfile
	 * is over the rotation threshold.
	 */
	if (l->total_bytes > l->threshold) {
		rc = audit_log_rotate(l);
	}

	return rc;
}

audit_log *audit_log_open(const char *logfile, const char *rotatefile, size_t threshold) {

	int rc;
	audit_log *l = NULL;
	struct stat log_file_stats;

	rc = stat(logfile, &log_file_stats);
	if (rc < 0 && errno != ENOENT) {
		SLOGE("Could not stat %s: %s\n",
			logfile, strerror(errno));
		return NULL;
	}

	/* The existing log had data */
	if (rc == 0 && log_file_stats.st_size != 0) {
		rc = rename(logfile, rotatefile);
		if (rc < 0) {
			SLOGE("Could not rename %s to %s: %s\n",
				logfile, rotatefile, strerror(errno));
			return NULL;
		}
	}

	l = calloc(sizeof(struct audit_log), 1);
	if (!l) {
		return NULL;
	}

	/* Open the output logfile */
	l->fd = open_log(logfile, AUDIT_LOG_FLAGS, AUDIT_LOG_MODE);
	if (l->fd < 0) {
	    /* Error message handled by open_log */
		return NULL;
	}

	l->rotatefile = strdup(rotatefile);
	if (!l->rotatefile) {
		goto err;
	}

	l->logfile = strdup(logfile);
	if (!l->logfile) {
		goto err;
	}
	l->threshold = threshold;

	return l;

err:
	audit_log_close(l);
	return NULL;
}

int audit_log_write_str(audit_log *l, const char *str) {

	if (l == NULL || str == NULL) {
		return -EINVAL;
	}

	return write_log(l, str, strlen(str));
}

int audit_log_write(audit_log *l, const struct audit_reply *reply) {

	if (l == NULL || reply == NULL) {
		return -EINVAL;
	}

	return write_log(l, reply->msg.data, reply->len);
}

int audit_log_rotate(audit_log *l) {

	int fd;
	int rc = 0;

	if (!l) {
		return -EINVAL;
	}

	rc = rename(l->logfile, l->rotatefile);
	if (rc < 0) {
		rc = -errno;
		SLOGE("Could not rename audit log file \"%s\" to \"%s\", error: %s\n",
			l->logfile, l->rotatefile, strerror(errno));
		return rc;
	}

	fd = open_log(l->logfile, AUDIT_LOG_FLAGS, AUDIT_LOG_MODE);
	if (fd < 0) {
	    return fd;
	}

	close(l->fd);
	l->total_bytes = 0;
	l->fd = fd;

	return 0;
}

void audit_log_close(audit_log *l) {

	if (l) {
		free(l->logfile);
		free(l->rotatefile);
		if (l->fd >= 0) {
			close(l->fd);
		}
		free(l);
	}
	return;
}

int audit_log_put_kmsg(audit_log *l) {

	char *tok;
	int rc = 0;
	char *buf = NULL;
	int len = klogctl(KLOG_SIZE_BUFFER, NULL, 0);

	/* No data to read */
	if(len == 0) {
	    return 0;
	}
	/* Data to read */
	else if (len > 0) {
		len++;
		buf = malloc(len * sizeof(*buf));
		if (!buf) {
			SLOGE("Out of memory\n");
			return -ENOMEM;
		}
	}
	/* Error */
	else {
		rc = -errno;
		SLOGE("Could not read logs: %s\n",
				strerror(errno));
		goto err;
	}

	rc = klogctl(KLOG_READ_ALL, buf, len);
	if (rc < 0) {
		rc = -errno;
		SLOGE("Could not read logs: %s\n",
				strerror(errno));
		goto err;
	}

	buf[len-1] = '\0';
	tok = buf;

	while((tok = strtok(tok, "\r\n"))) {
		if (strstr(tok, " audit(")) {
			audit_log_write_str(l, tok);
		}
		tok = NULL;
	}

err:
	free(buf);
	return rc;
}

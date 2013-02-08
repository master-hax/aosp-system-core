#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/klog.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "libaudit.h"
#include "audit_log.h"
#include "auditd.h"

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
 * Writes data pointed by buf to audit log, appends a trailing newline.
 * @param l
 *  The log to write, MUST NOT BE NULL!
 * @param buf
 *  The data to write, MUST NOT BE NULL!
 * @param len
 *  The length of the data
 * @return
 *  0 on success
 */
static int write_log(audit_log *l, const void *buf, size_t len) {

	int rc = 0;
	ssize_t bytes = 0;

	/*
	 * Ensure that the pointer offset and
	 * number of bytes written are the same
	 * size. Avoid char *, as on esoteric
	 * systems that are not byte addressable
	 * it could be defined as something else.
	 */
	const uint8_t *b = (uint8_t *)buf;

	do {
		bytes = write(l->fd, b, len);
		if (bytes < 0) {
			if (errno != EINTR) {
				rc = errno;
				ERROR("Error writing to audit log: %s, error: %s\n",
				l->logfile, strerror(rc));
				goto out;
			}
			/*
			 * If their was no forward progress made
			 * on the write do to EINTR, then keep trying
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
	 * from above.
	 */
	bytes = write(l->fd, "\n", 1);
	l->total_bytes += (bytes > 0) ? bytes : 0;

	/*
	 * Always attempt to rotate, even in the
	 * face of errors above
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
		ERROR("Could not stat %s: %s\n",
			logfile, strerror(errno));
		goto err;
	}

	/* The existing log had data */
	if (rc == 0 && log_file_stats.st_size != 0) {
		rc = rename(logfile, rotatefile);
		if (rc < 0) {
			ERROR("Could not rename %s to %s: %s\n",
				logfile, rotatefile, strerror(errno));
			goto err;
		}
	}

	l = calloc(sizeof(struct audit_log), 1);
	if (!l) {
		goto err;
	}

	/* Open the output logfile */
	l->fd = open(logfile, AUDIT_LOG_FLAGS, AUDIT_LOG_MODE);
	if (l->fd < 0) {
		ERROR("Could not open %s: %s\n",
			logfile, strerror(errno));
		goto err;
	}
	fchmod(l->fd, AUDIT_LOG_MODE);

	l->rotatefile = strdup(rotatefile);
	if (!l->rotatefile) {
		goto err;
	}

	l->logfile = strdup(logfile);
	if (!l->logfile) {
		goto err;
	}
	l->threshold = threshold;

out:
	return l;

err:
	audit_log_close(l);
	return NULL;
}

int audit_log_write_str(audit_log *l, const char *str) {

	if (l == NULL || str == NULL) {
		return EINVAL;
	}

	return write_log(l, str, strlen(str));
}

int audit_log_write(audit_log *l, const struct audit_reply *reply) {

	int rc = EINVAL;
	if (l && reply) {
		rc = write_log(l, reply->msg.data, reply->len);
	}
	return rc;
}

int audit_log_rotate(audit_log *l) {

	int rc = 0;
	if (!l) {
		rc = EINVAL;
		goto out;
	}

	rc = rename(l->logfile, l->rotatefile);
	if (rc < 0) {
		rc = errno;
		goto out;
	}

	close(l->fd);
	l->total_bytes = 0;

	l->fd = open(l->logfile, AUDIT_LOG_FLAGS, AUDIT_LOG_MODE);
	if (l->fd < 0) {
		rc = errno;
		goto out;
	}
	fchmod(l->fd, AUDIT_LOG_MODE);

out:
	return rc;
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

	if (len > 0) {
		len++;
		buf = malloc(len * sizeof(*buf));
		if (!buf) {
			rc = ENOMEM;
			ERROR("Out of memory\n");
			goto err;
		}
	}
	else if(len < 0) {
		rc = errno;
		ERROR("Could not read logs: %s\n",
				strerror(errno));
		goto err;
	}
	else {
		goto err;
	}

	rc = klogctl(KLOG_READ_ALL, buf, len);
	if (rc < 0) {
		rc = errno;
		ERROR("Could not read logs: %s\n",
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
	return 0;
}

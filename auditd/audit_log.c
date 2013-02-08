#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/klog.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "libaudit.h"
#include "audit_log.h"
#include "auditd.h"

#define MODE (S_IRUSR | S_IWUSR | S_IRGRP)
#define FLAGS (O_RDWR | O_CREAT | O_SYNC)

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
 *  The log to write
 * @param buf
 *  The data to write
 * @param len
 *  The length of the data
 * @return
 */
static int write_log(audit_log *l, const void *buf, size_t len) {

	int rc = 0;
	ssize_t bytes = 0;
	size_t total_bytes = 0;

	if(!l) {
		rc = EINVAL;
		goto err;
	}

	do {
		bytes += write(l->fd, buf, len);
		if(bytes < 0) {
			rc = errno;
			goto err;
		}
		total_bytes += bytes;
	} while (total_bytes != len);

	write(l->fd, "\n", 1);
	l->total_bytes += bytes + 1;

	if(l->total_bytes > l->threshold) {
		rc = audit_log_rotate(l);
	}

out:
	return rc;
err:
	goto out;
}

audit_log *audit_log_open(const char *logfile, const char *rotatefile, size_t threshold) {

	int fd = -1;
	audit_log *l = NULL;
	struct stat log_file_stats;

	if (stat(logfile, &log_file_stats) < 0) {
		if (errno != ENOENT) {
			ERROR("Could not stat %s: %s\n",
				logfile, strerror(errno));
			goto err;
		}
	}
	/* The existing log had data */
	else if (log_file_stats.st_size != 0){
		if (rename(logfile, rotatefile) < 0) {
			ERROR("Could not rename %s to %s: %s\n",
				logfile, rotatefile, strerror(errno));
			goto err;
		}
	}

	/* Open the output logfile */
	fd = open(logfile, FLAGS, MODE);
	if (fd < 0) {
		ERROR("Could not open %s: %s\n",
			logfile, strerror(errno));
		goto err;
	}
	fchmod(fd, MODE);

	l = calloc(sizeof(struct audit_log), 1);
	if (!l) {
		goto err;
	}
	l->rotatefile = strdup(rotatefile);
	if (!l->rotatefile) {
		goto err;
	}

	l->logfile = strdup(logfile);
	if (!l->logfile) {
		goto err;
	}
	l->fd = fd;
	l->threshold = threshold;

out:
	return l;

err:
	if (!(fd < 0)) {
		close(fd);
	}

	if (l && l->logfile) {
		free(l->logfile);
	}

	if (l && l->rotatefile) {
		free(l->rotatefile);
	}

	if (l) {
		free(l);
		l = NULL;
	}

	goto out;
}

int audit_log_write_str(audit_log *l, const char *str) {
	return write_log(l, str, strlen(str));
}

int audit_log_write(audit_log *l, const struct audit_reply *reply) {
	return write_log(l, reply->msg.data, reply->len);
}

int audit_log_rotate(audit_log *l) {
	int rc = 0;
	if(!l) {
		rc = EINVAL;
		goto err;
	}

	rc = rename(l->logfile, l->rotatefile);
	if (rc < 0) {
		rc = errno;
		goto err;
	}

	close(l->fd);
	l->total_bytes = 0;

	l->fd = open(l->logfile, FLAGS, MODE);
	if(l->fd < 0) {
		rc = errno;
		goto err;
	}
	fchmod(l->fd, MODE);

out:
	return rc;
err:
	goto out;
}

void audit_log_close(audit_log *l) {
	if(l) {
		if(l->logfile) {
			free(l->logfile);
		}
		if(l->rotatefile) {
			free(l->rotatefile);
		}
		if(l->fd >= 0) {
			close(l->fd);
		}
		free(l);
		l = NULL;
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
			ERROR("Out of memory\n");
			rc = ENOMEM;
			goto err;
		}
	}
	else if(len < 0) {
		ERROR("Could not read logs: %s\n",
				strerror(errno));
		rc = errno;
		goto err;
	}

	rc = klogctl(KLOG_READ_ALL, buf, len);
	if(rc < 0) {
		ERROR("Could not read logs: %s\n",
				strerror(errno));
		rc = errno;
		goto err;
	}

	buf[len-1] = '\0';
	tok = buf;

	while((tok = strtok(tok, "\r\n"))) {
		if(strstr(tok, " audit(")) {
			audit_log_write_str(l, tok);
		}
		tok = NULL;
	}

err:
	if (buf) {
		free(buf);
	}

	return 0;
}

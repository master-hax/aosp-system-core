
#include "cutils/uio.h"

#ifndef _FAKE_LOG_H
#define _FAKE_LOG_H

int fakeLogOpen(const char *pathName, int flags);
int fakeLogClose(int fd);
ssize_t fakeLogWritev(int fd, const struct iovec* vector, int count);

#endif /* _FAKE_LOG_H */

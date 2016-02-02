/*
 * Copyright (C) 2008 The Android Open Source Project
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
 * Implementation of the user-space ashmem API for devices, which have our
 * ashmem-enabled kernel. See ashmem-sim.c for the "fake" tmp-based version,
 * used by the simulator.
 */
#define LOG_TAG "ashmem"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/ashmem.h>

#include <cutils/ashmem.h>
#include <log/log.h>

#define ASHMEM_DEVICE "/dev/ashmem"

/* ashem identity */
static atomic_int_fast64_t __ashmem_rdev;

/* logistics of getting file descriptor for ashmem */
static int __ashmem_open()
{
    int fd, ret;
    struct stat st;

    fd = ret = TEMP_FAILURE_RETRY(open(ASHMEM_DEVICE, O_RDWR));
    if (ret < 0) {
        goto error;
    }

    ret = TEMP_FAILURE_RETRY(fstat(fd, &st));
    if (ret < 0) {
        goto error;
    }
    if (!S_ISCHR(st.st_mode)) {
        ret = -ENOTTY;
        goto error;
    }

    atomic_store(&__ashmem_rdev, (int64_t)st.st_rdev);
    return fd;

error:
    if ((ret == -1) && errno) {
        ret = -errno;
    }
    close(fd);
    return ret;
}

/* Make sure file descriptor references ashmem, negative number means false */
static int __ashmem_is_ashmem(int fd)
{
    dev_t rdev;
    struct stat st;
    int ret;

    if (fd < 0) {
        return fd;
    }

    ret = TEMP_FAILURE_RETRY(fstat(fd, &st));
    if (ret < 0) {
        goto error;
    }

    if (!S_ISCHR(st.st_mode) || !st.st_rdev) {
        rdev = atomic_load(&__ashmem_rdev); /* suppress uninitialized use */
        if (!rdev) {
            rdev = makedev(10, 50); /* low cost WAG, as long as not zero */
        }
        goto failed;
    }

    rdev = atomic_load(&__ashmem_rdev);
    if (!rdev) {
        ret = __ashmem_open();
        if (ret < 0) {
            return ret;
        }
        close(ret);
        rdev = atomic_load(&__ashmem_rdev);
        if (!rdev) {
            goto failed;
        }
    }

    if (st.st_rdev == rdev) {
        return 0;
    }

failed:
    ALOGE("illegal fd=%d mode=0%o rdev=%d:%d expected 0%o %d:%d",
        fd, st.st_mode, major(st.st_rdev), minor(st.st_rdev),
        S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IRGRP,
        major(rdev), minor(rdev));

    ret = -ENOTTY;

error:
    if ((ret == -1) && errno) {
        ret = -errno;
    }
    return ret;
}

/*
 * ashmem_create_region - creates a new ashmem region and returns the file
 * descriptor, or <0 on error
 *
 * `name' is an optional label to give the region (visible in /proc/pid/maps)
 * `size' is the size of the region, in page-aligned bytes
 */
int ashmem_create_region(const char *name, size_t size)
{
    int fd, ret;

    fd = ret = __ashmem_open();
    if (ret < 0) {
        return ret;
    }

    if (name) {
        char buf[ASHMEM_NAME_LEN] = {0};

        strlcpy(buf, name, sizeof(buf));
        ret = TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_NAME, buf));
        if (ret < 0) {
            goto error;
        }
    }

    ret = TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_SIZE, size));
    if (ret < 0) {
        goto error;
    }

    return fd;

error:
    if ((ret == -1) && errno) {
        ret = -errno;
    }
    close(fd);
    return ret;
}

int ashmem_set_prot_region(int fd, int prot)
{
    int ret = __ashmem_is_ashmem(fd);
    if (ret < 0) {
        return ret;
    }

    ret = TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_PROT_MASK, prot));
    if ((ret == -1) && errno) {
        return -errno;
    }
    return ret;
}

int ashmem_pin_region(int fd, size_t offset, size_t len)
{
    struct ashmem_pin pin = { offset, len };

    int ret = __ashmem_is_ashmem(fd);
    if (ret < 0) {
        return ret;
    }

    ret = TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_PIN, &pin));
    if ((ret == -1) && errno) {
        return -errno;
    }
    return ret;
}

int ashmem_unpin_region(int fd, size_t offset, size_t len)
{
    struct ashmem_pin pin = { offset, len };

    int ret = __ashmem_is_ashmem(fd);
    if (ret < 0) {
        return ret;
    }

    ret = TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_UNPIN, &pin));
    if ((ret == -1) && errno) {
        return -errno;
    }
    return ret;
}

int ashmem_get_size_region(int fd)
{
    int ret = __ashmem_is_ashmem(fd);
    if (ret < 0) {
        return ret;
    }

    ret = TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_GET_SIZE, NULL));
    if ((ret == -1) && errno) {
        return -errno;
    }
    return ret;
}

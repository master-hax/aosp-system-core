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

#include <cutils/ashmem.h>

/*
 * Implementation of the user-space ashmem API for devices, which have our
 * ashmem-enabled kernel. See ashmem-sim.c for the "fake" tmp-based version,
 * used by the simulator.
 */
#define LOG_TAG "ashmem"

#include <errno.h>
#include <fcntl.h>
#include <linux/ashmem.h>
#include <linux/memfd.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>
#include <log/log.h>
#include <android-base/unique_fd.h>
#include <android-base/properties.h>
#include <atomic>

#define ASHMEM_DEVICE "/dev/ashmem"
#define UNUSED __attribute__((unused))

/* Will be added to UAPI once upstream change is merged */
#define F_SEAL_FUTURE_WRITE 0x0010

/*
 * The minimum vendor API level at and after which it is safe to use memfd.
 * This is to facilitate deprecation of ashmem.
 */
#define MIN_MEMFD_VENDOR_API_LEVEL 29
#define MIN_MEMFD_VENDOR_API_LEVEL_CHAR 'Q'

/* ashmem identity */
static dev_t __ashmem_rdev;
/*
 * If we trigger a signal handler in the middle of locked activity and the
 * signal handler calls ashmem, we could get into a deadlock state.
 */
static pthread_mutex_t __ashmem_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * has_memfd_support() determines if the device can use memfd. memfd support
 * has been there for long time, but certain things in it may be missing.  We
 * check for needed support in it. Also we check if the VNDK version of
 * libcutils being used is new enough, if its not, then we cannot use memfd
 * since the older copies may be using ashmem so we just use ashmem. Once all
 * Android devices that are getting updates are new enough (ex, they were
 * originally shipped with Android release > P), then we can just use memfd and
 * delete all ashmem code from libcutils (while preserving the interface).
 */

/* NOTE:
 * Temporarily disable memfd, till vendor and apps are ready for it.
 *
 * The main issue: either apps or vendor processes can directly make ashmem
 * IOCTLs on FDs they receive by assuming they are ashmem, without going
 * through libcutils. Such fds could have very well be originally created with
 * libcutils hence they could be memfd. Thus the IOCTLs will break.
 *
 * Set default value of memfd_supported to -1 once the issue is resolved.
 */
static std::atomic<int> memfd_supported = 0;

static int debug_log = 0;    /* For debugging: set to 1 for verbose debug logging */
static int pin_deprecation_warn = 1; /* Log the pin deprecation warning only once */

static bool no_memfd_support()
{
    memfd_supported = 0;
    ALOGI("memfd: Device cannot use memfd, using ashmem.\n");
    return false;
}

static bool has_memfd_support()
{
    if (memfd_supported == 1) {
        return true;
    } else if (memfd_supported == 0) {
        return false;
    }

    std::string vndk_version = android::base::GetProperty("ro.vndk.version", "");
    char *p;
    long int vers = strtol(vndk_version.c_str(), &p, 10);
    bool vndk_version_is_number = (*p == 0);

    if (!vndk_version_is_number && vndk_version != "current") {
        /* Version is a string */

        if (tolower(vndk_version[0]) < 'a' || tolower(vndk_version[0]) > 'z') {
            ALOGE("memfd: ro.vndk.version not defined or invalid (%s), this is mandated since P.\n",
                  vndk_version.c_str());
            return no_memfd_support();
        }

        /*
         * If VNDK is using older libcutils, don't use memfd This is so that
         * the same shared memory mechanism is used across binder transactions
         * between vendor partition processes and system partition processes.
         */
        if (tolower(vndk_version[0]) < tolower(MIN_MEMFD_VENDOR_API_LEVEL_CHAR)) {
            ALOGI("memfd: device is using VNDK version (%s) which is less than Q. Use ashmem only.\n",
                  vndk_version.c_str());
            return no_memfd_support();
        }
    } else if (vndk_version != "current") {
        /* Version is a number */

        /* strtol treats empty strings as numbers, so we end up here */
        if ((vndk_version == "")) {
            ALOGE("memfd: ro.vndk.version not defined or invalid (%s), this is mandated since P.\n",
                    vndk_version.c_str());
            return no_memfd_support();
        }

        if (vers < MIN_MEMFD_VENDOR_API_LEVEL) {
            ALOGI("memfd: device is using VNDK version (%s) which is less than Q. Use ashmem only.\n",
                  vndk_version.c_str());
            return no_memfd_support();
        }
    }

    android::base::unique_fd fd(syscall(__NR_memfd_create, "test_android_memfd", MFD_ALLOW_SEALING));
    if (fd < 0) {
        ALOGE("memfd: kernel does not have memfd support needed\n");
        return no_memfd_support();
    }

    if (fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) < 0) {
        ALOGE("memfd: kernel does not have memfd support needed. fcntl missing.\n");
        return no_memfd_support();
    }

    memfd_supported = 1;
    if (debug_log) {
       ALOGD("memfd: device has memfd support, using it\n");
    }

    return true;
}

/* logistics of getting file descriptor for ashmem */
static int __ashmem_open_locked()
{
    int ret;
    struct stat st;

    int fd = TEMP_FAILURE_RETRY(open(ASHMEM_DEVICE, O_RDWR | O_CLOEXEC));
    if (fd < 0) {
        return fd;
    }

    ret = TEMP_FAILURE_RETRY(fstat(fd, &st));
    if (ret < 0) {
        int save_errno = errno;
        close(fd);
        errno = save_errno;
        return ret;
    }
    if (!S_ISCHR(st.st_mode) || !st.st_rdev) {
        close(fd);
        errno = ENOTTY;
        return -1;
    }

    __ashmem_rdev = st.st_rdev;
    return fd;
}

static int __ashmem_open()
{
    int fd;

    pthread_mutex_lock(&__ashmem_lock);
    fd = __ashmem_open_locked();
    pthread_mutex_unlock(&__ashmem_lock);

    return fd;
}

/* Make sure file descriptor references ashmem, negative number means false */
static int __ashmem_is_ashmem(int fd, int fatal)
{
    dev_t rdev;
    struct stat st;

    if (fstat(fd, &st) < 0) {
        return -1;
    }

    rdev = 0; /* Too much complexity to sniff __ashmem_rdev */
    if (S_ISCHR(st.st_mode) && st.st_rdev) {
        pthread_mutex_lock(&__ashmem_lock);
        rdev = __ashmem_rdev;
        if (rdev) {
            pthread_mutex_unlock(&__ashmem_lock);
        } else {
            int fd = __ashmem_open_locked();
            if (fd < 0) {
                pthread_mutex_unlock(&__ashmem_lock);
                return -1;
            }
            rdev = __ashmem_rdev;
            pthread_mutex_unlock(&__ashmem_lock);

            close(fd);
        }

        if (st.st_rdev == rdev) {
            return 0;
        }
    }

    if (fatal) {
        if (rdev) {
            LOG_ALWAYS_FATAL("illegal fd=%d mode=0%o rdev=%d:%d expected 0%o %d:%d",
              fd, st.st_mode, major(st.st_rdev), minor(st.st_rdev),
              S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IRGRP,
              major(rdev), minor(rdev));
        } else {
            LOG_ALWAYS_FATAL("illegal fd=%d mode=0%o rdev=%d:%d expected 0%o",
              fd, st.st_mode, major(st.st_rdev), minor(st.st_rdev),
              S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IRGRP);
        }
        /* NOTREACHED */
    }

    errno = ENOTTY;
    return -1;
}

static int __ashmem_check_failure(int fd, int result)
{
    if (result == -1 && errno == ENOTTY) __ashmem_is_ashmem(fd, 1);
    return result;
}

static int fd_check_error_once = 0;

static bool memfd_is_ashmem(int fd)
{
   if (__ashmem_is_ashmem(fd, 0) == 0) {
      if (!fd_check_error_once) {
         ALOGE("memfd: memfd expected but ashmem fd being used - please use libcutils.\n");
         fd_check_error_once = 1;
      }

      return true;
   }

   return false;
}

int ashmem_valid(int fd)
{
    if (has_memfd_support() && !memfd_is_ashmem(fd)) {
        return 1;
    }

    return __ashmem_is_ashmem(fd, 0) >= 0;
}

static int memfd_create_region(const char *name, size_t size)
{
    int fd;

    fd = syscall(__NR_memfd_create, name, MFD_ALLOW_SEALING);
    if (fd < 0) {
        ALOGE("memfd: create: name: %s, size: %zd, error fd %d, errno %s\n",
              name, size, fd, strerror(errno));
        goto error;
    }

   if (ftruncate(fd, size) == -1) {
        ALOGE("memfd: create: truncate error. name: %s, size: %zd, errno: %s\n",
              name, size, strerror(errno));
        goto error;
    }

    if (debug_log) {
       ALOGD("memfd: created region with name: %s, size: %zd, fd: %d\n", name, size, fd);
    }

    return fd;
error:
    ALOGE("memfd: error creating region with name: %s, size: %zd, err: %s\n", name, size, strerror(errno));
    close(fd);
    return -1;
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
    int ret, save_errno;

    if (has_memfd_support()) {
        return memfd_create_region(name ? name : "none", size);
    }

    int fd = __ashmem_open();
    if (fd < 0) {
        return fd;
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
    save_errno = errno;
    close(fd);
    errno = save_errno;
    return ret;
}

static int memfd_set_prot_region(int fd, int prot)
{
    int ret;

    /* Only proceed if an fd needs to be write-protected */
    if (prot & PROT_WRITE) {
       return 0;
    }

    ret = fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE);
    if (ret < 0) {
       ALOGE("F_SEAL_FUTURE_WRITE seal failed: %s\n", strerror(errno));
    }
    return ret;
}

int ashmem_set_prot_region(int fd, int prot)
{
    if (has_memfd_support() && !memfd_is_ashmem(fd)) {
        return memfd_set_prot_region(fd, prot);
    }

    return __ashmem_check_failure(fd, TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_PROT_MASK, prot)));
}

int ashmem_pin_region(int fd UNUSED, size_t offset UNUSED, size_t len UNUSED)
{
    if (!pin_deprecation_warn || debug_log) {
        ALOGE("Pinning is deprecated since Android Q. Please use trim or other methods.\n");
        pin_deprecation_warn = 1;
    }

    if (has_memfd_support() && !memfd_is_ashmem(fd)) {
       return 0;
    }

    // TODO: should LP64 reject too-large offset/len?
    ashmem_pin pin = { static_cast<uint32_t>(offset), static_cast<uint32_t>(len) };
    return __ashmem_check_failure(fd, TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_PIN, &pin)));
}

int ashmem_unpin_region(int fd UNUSED, size_t offset UNUSED, size_t len UNUSED)
{
    if (!pin_deprecation_warn || debug_log) {
        ALOGE("Pinning is deprecated since Android Q. Please use trim or other methods.\n");
        pin_deprecation_warn = 1;
    }

    if (has_memfd_support() && !memfd_is_ashmem(fd)) {
       return 0;
    }

    // TODO: should LP64 reject too-large offset/len?
    ashmem_pin pin = { static_cast<uint32_t>(offset), static_cast<uint32_t>(len) };
    return __ashmem_check_failure(fd, TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_UNPIN, &pin)));
}

int ashmem_get_size_region(int fd)
{
    int ret;
    struct stat sb;

    if (has_memfd_support() && !memfd_is_ashmem(fd)) {
        ret = fstat(fd, &sb);
        if (ret < 0) {
            ALOGE("fstat failed: err %s\n", strerror(errno));
        }

        if (debug_log) {
           ALOGD("memfd: get size on fd %d return %d\n", fd, (int)sb.st_size);
        }

        return sb.st_size;
    }

    return __ashmem_check_failure(fd, TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_GET_SIZE, NULL)));
}

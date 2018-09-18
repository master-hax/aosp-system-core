/*
 * Copyright (C) 2018 The Android Open Source Project
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
#include <error.h>
#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <linux/reboot.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MS_MOVE
#define MS_MOVE 8192
#endif
#define DEV_MAJOR_ZRAM 254
#define DEV_MAJOR_DM 236

#define ERROR(...) error(EXIT_FAILURE, errno, ##__VA_ARGS__)

static char* str(const char* fmt, ...) {
    static char buf[_POSIX_PATH_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return buf;
}

static int exists(const char* pathfmt, ...) {
    char buf[_POSIX_PATH_MAX];
    va_list ap;
    va_start(ap, pathfmt);
    vsnprintf(buf, sizeof(buf), pathfmt, ap);
    va_end(ap);
    return access(buf, F_OK) == 0;
}

int clone(int (*fn)(void*), void* child_stack, int flags, void* arg, ...
          /* pid_t *ptid, void *newtls, pid_t *ctid */);

static int ucontainer_child_main(void* arg) {
    int fd = 0, maxfd = 0;
    char** p = 0;
    char** argv = (char**)arg;
    char* child_root = *argv++;

    printf("child_root = %s\n", child_root);
    printf("child_argv = ");
    for (p = argv; *p; p++) {
        printf("%s ", *p);
    }
    printf("\n");
    if (getpid() != 1) {
        fprintf(stderr, "pid != 1\n");
        exit(EXIT_FAILURE);
    }
    if (strcmp(child_root, "/") != 0) {
        dev_t rootdev = 0;
        struct stat st;
        memset(&st, 0, sizeof(st));
        if (chdir(child_root) != 0) {
            ERROR("chdir err");
        }
        stat("/", &st);
        rootdev = st.st_dev;
        stat(".", &st);
        if (st.st_dev == rootdev) {
            fprintf(stderr, "child_root can't be in the same filesystem with '/' \n");
            exit(EXIT_FAILURE);
        }
        if (mount(".", "/", 0, MS_MOVE, 0) != 0) {
            ERROR("mount err");
        }
        if (chroot(".") != 0) {
            ERROR("chroot err");
        }
    }
    maxfd = sysconf(_SC_OPEN_MAX);
    for (fd = 3; fd < maxfd; fd++) {
        close(fd);
    }
    if (execv(argv[0], argv) != 0) {
        ERROR("exec err");
    }
    return EXIT_FAILURE;
}

static int stop() {
    const char* SEPATH = "/sys/fs/selinux/enforce";
    const char* DMPATH = "/dev/device-mapper";
    int sefd = -1, fd = -1;
    struct dm_ioctl io;
    memset(&io, 0, sizeof(io));

    if ((sefd = open(SEPATH, O_RDWR | O_CLOEXEC)) < 0) {
        ERROR("fail to open %s", SEPATH);
    }
    if (write(sefd, "0", strlen("0")) < 0) {
        ERROR("fail to write %s", SEPATH);
    }
    close(sefd);

    if (!exists(DMPATH)) {
        if (mknod(DMPATH, S_IFCHR, makedev(10, DEV_MAJOR_DM))) {
            ERROR("fail to mknod %s", DMPATH);
        }
    }
    fd = open(DMPATH, O_RDWR);
    if (fd < 0) {
        ERROR("fail to open %s", DMPATH);
    }
    io.version[0] = 4;
    io.data_size = sizeof(io);

    // Clean up remnant vendor DM device so subsequent creates will succeed
    if (ioctl(fd, DM_REMOVE_ALL, &io) != 0) {
        ERROR("device-mapper ioctl err");
    }
    return 0;
}

// the reason to exit ucontainer
typedef enum { UC_REBOOT, UC_POWEROFF, UC_UNKNOWN } uc_exit_t;

static uc_exit_t ucontainer_exit(const char* exe_path, uc_exit_t status, const char* msg) {
    // self execute to acquire the selinux context.
    system(str("%s stop", exe_path));
    printf("ucontainer_exit: %s\n", msg);
    return status;
}

static uc_exit_t ucontainer(const char* exe_path, const char** argv) {
#define UC_EXIT(_reason) ucontainer_exit(exe_path, _reason, #_reason)

    const int stack_size = 1024 * 1024;
    const char* timeout = *argv++;
    int child_pid = clone(ucontainer_child_main, (char*)malloc(stack_size) + stack_size,
                          CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWPID | SIGCHLD, argv);
    if (child_pid < 0) {
        ERROR("fail to clone");
    }
    printf("timeout = %s sec.\n", timeout);
    if (strcmp(timeout, "0") != 0) {
        sleep(atoi(timeout));
        printf("ucountiner KILL\n");
        kill(child_pid, SIGABRT);
        return UC_EXIT(UC_UNKNOWN);
    } else {
        int status = 0;
        if (waitpid(child_pid, &status, 0) <= 0) {
            ERROR("failed waiting for child to exit");
        }
        // If the child process is init then a reboot or shutdown within
        // the container will result in these particular values
        switch (status) {
            case SIGHUP:
                return UC_EXIT(UC_REBOOT);
            case SIGINT:
                return UC_EXIT(UC_POWEROFF);
            default:
                UC_EXIT(UC_UNKNOWN);
                // UC_EXIT first to make sure the console is accessible
                fprintf(stderr, "unknown child status %d\n", status);
                return UC_UNKNOWN;
        }
    }
#undef UC_EXIT
}

static void mkdir_p(const char* dir) {
    if (!exists(dir) && mkdir(dir, 0700) != 0) {
        ERROR("fail to mkdir %s", dir);
    }
}

static int start(const char* exe_path) {
    const char* argv[] = {"0", "/", "/init", 0};
    int i = 0;
    int ret = ucontainer(exe_path, argv);
    printf("exit ucontainer with %d\n", ret);

    if (mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755") != 0) {
        ERROR("fail to mount tmpfs -> /dev");
    }
    if (mount("tmpfs", "/mnt", "tmpfs", MS_NOSUID, "mode=0755") != 0) {
        ERROR("fail to mount tmpfs -> /mnt");
    }
    mkdir_p("/dev/block");
    for (i = 0; i < 4; i++) {
        printf("detect zram%d\n", i);
        if (!exists("/dev/block/zram%d", i)) {
            dev_t dev = makedev(DEV_MAJOR_ZRAM, i);
            if (mknod(str("/dev/block/zram%d", i), S_IFBLK, dev) != 0) {
                ERROR("fail to mknod /dev/block/zram%d", i);
            }
        }
        mkdir_p(str("/mnt/zram%d", i));
        // the system image fetched from GCE is in ext4
        if (mount(str("/dev/block/zram%d", i), str("/mnt/zram%d", i), "ext4", 0, 0) == 0 &&
            exists("/mnt/zram%d/system/bin/ls", i)) {
            argv[1] = strdup(str("/mnt/zram%d", i));
            ret = ucontainer(exe_path, argv);
            printf("exit from live image with %d\n", ret);
            break;
        } else {
            printf("not a system partition\n");
        }
    }
    if (ret == UC_POWEROFF) {
        // power off
        printf("reboot(%d)\n", RB_POWER_OFF);
        reboot(RB_POWER_OFF);
    } else {
        // reboot
        printf("reboot(%d)\n", RB_AUTOBOOT);
        reboot(RB_AUTOBOOT);
    }
    return 0;
}

static int usage() {
    printf("Usage:\n");
    printf("    ucontainer      : start ucontainer for live image\n");
    printf("    ucontainer stop : clean up system status\n");
    printf("    ucontainer $timeout $root $executable: execute an executable with ucontainer\n");
    return EXIT_FAILURE;
}

int main(int argc, const char** argv) {
    const char* exe_path = argv[0];
    if (argc == 1) {
        printf("%s start\n", exe_path);
        return start(exe_path);
    } else if (argc > 1 && strcmp(argv[1], "stop") == 0) {
        printf("%s stop\n", exe_path);
        return stop();
    } else if (argc < 3) {
        return usage();
    } else {
        return ucontainer(exe_path, argv);
    }
}

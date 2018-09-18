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

static char exe_path[64];

static char buf[64];

static char* strfmt(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return buf;
}

static int exe(const char* cmdfmt, ...) {
    va_list ap;
    va_start(ap, cmdfmt);
    vsnprintf(buf, sizeof(buf), cmdfmt, ap);
    va_end(ap);
    return system(buf);
}

static int exists(const char* pathfmt, ...) {
    va_list ap;
    va_start(ap, pathfmt);
    vsnprintf(buf, sizeof(buf), pathfmt, ap);
    va_end(ap);
    return access(buf, F_OK) == 0;
}

int clone(int (*fn)(void*), void* child_stack, int flags, void* arg, ...
          /* pid_t *ptid, void *newtls, pid_t *ctid */);

static char stack[1024 * 1024];

static int ucontainer_main(void* arg) {
    dev_t rootdev;
    int err, fd, maxfd;
    char **p, **argv;
    char* child_root;
    struct stat st;

    argv = (char**)arg;
    child_root = *argv++;
    printf("child_root = %s\n", child_root);
    printf("child_argv = %s\n", *argv);
    for (p = argv + 1; *p; p++) printf("%s ", *p);
    if ((err = getpid() != 1)) {
        printf("pid != 1\n");
        exit(err);
    }
    if (strcmp(child_root, "/") != 0) {
        if ((err = chdir(child_root))) {
            perror("chdir err");
            exit(err);
        }
        stat("/", &st);
        rootdev = st.st_dev;
        stat(".", &st);
        if (st.st_dev == rootdev) {
            printf("child_root can't be in the same filesystem with '/' \n");
            exit(-1);
        }
        if ((err = mount(".", "/", NULL, MS_MOVE, NULL))) {
            perror("mount err");
            exit(err);
        }
        if ((err = chroot("."))) {
            perror("chroot err");
            exit(err);
        }
    }
    maxfd = sysconf(_SC_OPEN_MAX);
    for (fd = 3; fd < maxfd; fd++) {
        close(fd);
    }
    if ((err = execv(argv[0], argv))) {
        perror("exec err");
        exit(err);
    }
    return 1;
}

static int stop() {
    const char* SEPATH = "/sys/fs/selinux/enforce";
    const char* DMPATH = "/dev/device-mapper";
    int sefd, fd, ret;
    struct dm_ioctl io;

    if ((sefd = open(SEPATH, O_RDWR | O_CLOEXEC)) < 0) {
        perror(strfmt("fail to open %s\n", SEPATH));
        return -1;
    }
    if ((ret = write(sefd, "0", strlen("0"))) < 0) {
        perror(strfmt("fail to write %s\n", SEPATH));
        return ret;
    }
    close(sefd);

    if (!exists(DMPATH)) {
        if (mknod(DMPATH, S_IFCHR, makedev(10, DEV_MAJOR_DM))) {
            perror(strfmt("fail to mknod %s\n", DMPATH));
            return -1;
        }
    }
    fd = open(DMPATH, O_RDWR);
    if (fd < 0) {
        perror(strfmt("fail to open %s\n", DMPATH));
        return -1;
    }
    memset(&io, 0, sizeof(io));
    io.version[0] = 4;
    io.data_size = sizeof(io);

    // Clean up remnant vendor DM device so subsequent creates will succeed
    if ((ret = ioctl(fd, DM_REMOVE_ALL, &io)) != 0) {
        perror("device-mapper ioctl err");
        return ret;
    }
    return 0;
}

static int ucontainer_exit(int code, char* msg) {
    // execute to gain the selinux context
    exe("%s stop", exe_path);
    printf("%s %d\n", msg, code);
    return code;
}

static int ucontainer(const char** argv) {
    const char* timeout = *argv++;
    int child_pid;
    child_pid = clone(ucontainer_main, stack + sizeof(stack),
                      CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWPID | SIGCHLD, argv);
    printf("timeout = %s sec.\n", timeout);
    if (child_pid < 0) {
        perror("fail to clone");
        return -1;
    }
    if (strcmp(timeout, "0") != 0) {
        sleep(atoi(timeout));
        printf("ucountiner KILL\n");
        kill(child_pid, 6);
        return ucontainer_exit(3, "kill");
    } else {
        int status = 0;
        if (waitpid(child_pid, &status, 0) <= 0) {
            perror("failed waiting for child to exit");
            exit(EXIT_FAILURE);
        }
        // If the child process is init then a reboot or shutdown within
        // the container will result in these particular values
        if (status == SIGHUP) {
            return ucontainer_exit(1, "reboot");
        } else if (status == SIGINT) {
            return ucontainer_exit(2, "poweroff");
        } else {
            return ucontainer_exit(status, "unknown");
        }
    }
}

static int start() {
    const char* argv[] = {"0", "/", "/init", 0};
    int i, ret;
    ret = ucontainer(argv);
    printf("exit ucontainer with %d\n", ret);
    for (i = 0; i < 4; i++) {
        printf("detect zram%d\n", i);
        if (!exists("/dev/block/zram%d", i)) {
            dev_t dev = makedev(DEV_MAJOR_ZRAM, i);
            if (mknod(strfmt("/dev/block/zram%d", i), S_IFBLK, dev)) {
                perror(strfmt("fail to mknod /dev/block/zram%d\n", i));
                return -1;
            }
        }
        if (exe("/system/bin/mkdir -p /mnt/zram%d", i)) {
            fprintf(stderr, "fail to /system/bin/mkdir -p /mnt/zram%d\n", i);
            return -1;
        }
        // the system image fetched from GCE is in ext4
        if (exe("/system/bin/mount -t ext4 /dev/block/zram%d /mnt/zram%d", i, i) == 0 &&
            exists("/mnt/zram%d/system/bin/ls", i)) {
            char root[64];
            strcpy(root, strfmt("/mnt/zram%d", i));
            argv[1] = root;
            ret = ucontainer(argv);
            printf("exit from live image with %d\n", ret);
            break;
        } else {
            printf("not a system partition\n");
        }
    }
    if (ret == 1) {
        // reboot
        printf("reboot %d\n", RB_AUTOBOOT);
        reboot(RB_AUTOBOOT);
        return 0;
    } else if (ret == 2) {
        // power off
        printf("reboot %d\n", RB_POWER_OFF);
        reboot(RB_POWER_OFF);
        return 0;
    } else {
        fprintf(stderr, "unknown return code %d\n", ret);
        reboot(RB_AUTOBOOT);
        return -1;
    }
}

static int usage() {
    printf("Usage:\n");
    printf("    ucontainer      : start ucontainer for live image\n");
    printf("    ucontainer stop : clean up system status\n");
    printf("    ucontainer $root $executable: execute an executable with ucontainer\n");
    return 0;
}

int main(int argc, const char** argv) {
    strcpy(exe_path, argv[0]);
    if (argc == 1) {
        printf("%s start\n", argv[0]);
        return start();
    } else if (argc > 1 && strcmp(argv[1], "stop") == 0) {
        printf("%s stop\n", argv[0]);
        return stop();
    } else if (argc < 3) {
        return usage();
    } else {
        return ucontainer(argv);
    }
}

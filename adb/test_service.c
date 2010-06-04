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
 * Use the 'adb test' command when you're porting Android to a new device
 * and you can't seem to get /system/bin/sh to run and give output to the
 * serial console. This command will go step by step thru mounting /system
 * and report back on any error encountered.
 *
 * BE SURE that the defn's below (PARTN in particular) is the same as that
 * used in your /init.rc for mounting /system.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <errno.h>

#include "sysdeps.h"

#define  TRACE_TAG  TRACE_ADB
#include "adb.h"

#define CONSOLE "/dev/console"
#define TTYS0 "/dev/ttyS0"
#define DEVDR "/dev"
#define PARTN "/dev/block/mmcblk0p6"
#define MNTPT "/system"
#define FSTYP "ext3"

void vfdprintf(int fd, const char *fmt, ...)
{
    char buf[200];
    va_list ap;
 
    va_start(ap, fmt); 
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    writex(fd, buf, strlen(buf));
}

void cat_file(int fd_debug, char *file_path)
{
    int path_fd, rc;
    char buf[512];

    path_fd = adb_open(file_path, O_RDONLY);
    if (path_fd < 0) {
        vfdprintf(fd_debug, "Unable to open %s. errno=%d\n", file_path, errno);
        return;
    }
    vfdprintf(fd_debug, "Cat of %s:\n", file_path);
    while ((rc = adb_read(path_fd, buf, sizeof(buf))) > 0)
        writex(fd_debug, buf, rc);
    vfdprintf(fd_debug, "\n");

    adb_close(path_fd);
}

int do_test_service(int fd, void *cookie)
{
    struct stat sbuf;

    vfdprintf(fd, "Starting do_test_service\n");
    cat_file(fd, "/proc/partitions");
    cat_file(fd, "/proc/mounts");

    if (stat(DEVDR, &sbuf) != 0) 
        vfdprintf(fd, "FAIL: Stat of %s. errno=%d\n", DEVDR, errno); 
    else if (!S_ISDIR(sbuf.st_mode)) 
        vfdprintf(fd, "FAIL: %s is not a directory. mode=0%o\n", DEVDR, sbuf.st_mode); 
    else
        vfdprintf(fd, "PASS: %s\n", DEVDR);

    if (stat(CONSOLE, &sbuf) != 0) 
        vfdprintf(fd, "FAIL: Stat of %s. errno=%d\n", CONSOLE, errno); 
    else if (!S_ISCHR(sbuf.st_mode)) 
        vfdprintf(fd, "FAIL: %s is not a directory. mode=0%o\n", CONSOLE, sbuf.st_mode); 
    else
        vfdprintf(fd, "PASS: %s\n", CONSOLE);

    if (stat(TTYS0, &sbuf) != 0) 
        vfdprintf(fd, "FAIL: Stat of %s. errno=%d\n", TTYS0, errno); 
    else if (!S_ISCHR(sbuf.st_mode)) 
        vfdprintf(fd, "FAIL: %s is not a directory. mode=0%o\n", TTYS0, sbuf.st_mode); 
    else
        vfdprintf(fd, "PASS: %s\n", TTYS0);

    if (stat(PARTN, &sbuf) != 0) 
        vfdprintf(fd, "FAIL: Stat of %s. errno=%d\n", PARTN, errno); 
    else if (!S_ISBLK(sbuf.st_mode)) 
        vfdprintf(fd, "FAIL: %s is not a block device. mode=0%o\n", PARTN, sbuf.st_mode); 
    else
        vfdprintf(fd, "PASS: %s\n", PARTN);

    if (stat(MNTPT, &sbuf) != 0) 
        vfdprintf(fd, "FAIL: Stat of %s. errno=%d\n", MNTPT, errno); 
    else if (!S_ISDIR(sbuf.st_mode)) 
        vfdprintf(fd, "FAIL: %s is not a directory. mode=0%o\n", MNTPT, sbuf.st_mode); 
    else
        vfdprintf(fd, "PASS: %s\n", MNTPT);

    if (mount(PARTN, MNTPT, "ext3", 0, 0) != 0)
        vfdprintf(fd, "FAIL: mount of %s on %s (%s). errno=%d\n", PARTN, MNTPT, FSTYP, errno);
    else {
        vfdprintf(fd, "PASS: mount of %s on %s (%s)\n", PARTN, MNTPT, FSTYP);
        vfdprintf(fd, "NOTE: %s has been left mounted. Try 'adb shell' now.\n", MNTPT);
    }

    vfdprintf(fd, "\nCompleted do_test_service\n");
    return;
}

void test_service(int fd, void *cookie)
{
    do_test_service(fd, cookie);
    adb_close(fd);
}

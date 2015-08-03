/*
 * Copyright (C) 2007 The Android Open Source Project
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

#define TRACE_TAG TRACE_SYNC

#include "sysdeps.h"
#include "file_sync_service.h"

#include <dirent.h>
#include <errno.h>
#include <selinux/android.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>

#include "adb.h"
#include "adb_io.h"
#include "private/android_filesystem_config.h"

#include <base/stringprintf.h>
#include <base/strings.h>

static bool should_use_fs_config(const std::string& path) {
    // TODO: use fs_config to configure permissions on /data.
    return android::base::StartsWith(path, "/system/") ||
           android::base::StartsWith(path, "/vendor/") ||
           android::base::StartsWith(path, "/oem/");
}

static bool secure_mkdirs(const std::string& path) {
    uid_t uid = -1;
    gid_t gid = -1;
    unsigned int mode = 0775;
    uint64_t cap = 0;

    if (path[0] != '/') return false;

    std::vector<std::string> path_components = android::base::Split(path, "/");
    path_components.pop_back(); // For "/system/bin/sh", only create "/system/bin".

    std::string partial_path;
    for (auto& path_component : path_components) {
        if (partial_path.back() != OS_PATH_SEPARATOR) partial_path += OS_PATH_SEPARATOR;
        partial_path += path_component;

        if (should_use_fs_config(partial_path)) {
            fs_config(partial_path.c_str(), 1, &uid, &gid, &mode, &cap);
        }
        if (adb_mkdir(partial_path.c_str(), mode) == -1) {
            if (errno != EEXIST) {
                return false;
            }
        } else {
            if (chown(partial_path.c_str(), uid, gid) == -1) {
                return false;
            }
            selinux_android_restorecon(partial_path.c_str(), 0);
        }
    }
    return true;
}

static bool do_stat(int s, const char* path) {
    syncmsg msg;
    msg.stat.id = ID_STAT;

    struct stat st;
    memset(&st, 0, sizeof(st));
    // TODO: add a way to report that the stat failed!
    lstat(path, &st);
    msg.stat.mode = htoll(st.st_mode);
    msg.stat.size = htoll(st.st_size);
    msg.stat.time = htoll(st.st_mtime);

    return WriteFdExactly(s, &msg.stat, sizeof(msg.stat));
}

static bool do_list(int s, const char* path) {
    struct dirent *de;
    struct stat st;

    char tmp[1024 + 256 + 1];
    char *fname;

    size_t len = strlen(path);
    memcpy(tmp, path, len);
    tmp[len] = '/';
    fname = tmp + len + 1;

    syncmsg msg;
    msg.dent.id = ID_DENT;

    std::unique_ptr<DIR, int(*)(DIR*)> d(opendir(path), closedir);
    if (!d) goto done;

    while ((de = readdir(d.get()))) {
        size_t len = strlen(de->d_name);

        // not supposed to be possible, but
        // if it does happen, let's not buffer overrun.
        if (len > 256) continue;

        strcpy(fname, de->d_name);
        if (lstat(tmp, &st) == 0) {
            msg.dent.mode = htoll(st.st_mode);
            msg.dent.size = htoll(st.st_size);
            msg.dent.time = htoll(st.st_mtime);
            msg.dent.namelen = htoll(len);

            if (!WriteFdExactly(s, &msg.dent, sizeof(msg.dent)) ||
                    !WriteFdExactly(s, de->d_name, len)) {
                return false;
            }
        }
    }

done:
    msg.dent.id = ID_DONE;
    msg.dent.mode = 0;
    msg.dent.size = 0;
    msg.dent.time = 0;
    msg.dent.namelen = 0;
    return WriteFdExactly(s, &msg.dent, sizeof(msg.dent));
}

static bool fail_message(int s, const std::string& reason) {
    D("sync: failure: %s\n", reason.c_str());

    syncmsg msg;
    msg.data.id = ID_FAIL;
    msg.data.size = htoll(reason.size());
    return WriteFdExactly(s, &msg.data, sizeof(msg.data)) && WriteFdExactly(s, reason);
}

// TODO: callers of this have already failed, and should probably ignore its
// return value (http://b/23437039).
static bool fail_errno(int s) {
    return fail_message(s, strerror(errno));
}

static bool handle_send_file(int s, char *path, uid_t uid,
                             gid_t gid, mode_t mode, std::vector<char>& buffer, bool do_unlink) {
    syncmsg msg;
    unsigned int timestamp = 0;

    int fd = adb_open_mode(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if(fd < 0 && errno == ENOENT) {
        if (!secure_mkdirs(path)) {
            if (fail_errno(s)) return false;
            fd = -1;
        } else {
            fd = adb_open_mode(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
        }
    }
    if(fd < 0 && errno == EEXIST) {
        fd = adb_open_mode(path, O_WRONLY | O_CLOEXEC, mode);
    }
    if(fd < 0) {
        if (fail_errno(s)) return false;
        fd = -1;
    } else {
        if(fchown(fd, uid, gid) != 0) {
            fail_errno(s);
            errno = 0;
        }

        /*
         * fchown clears the setuid bit - restore it if present.
         * Ignore the result of calling fchmod. It's not supported
         * by all filesystems. b/12441485
         */
        fchmod(fd, mode);
    }

    while (true) {
        unsigned int len;

        if(!ReadFdExactly(s, &msg.data, sizeof(msg.data)))
            goto fail;

        if(msg.data.id != ID_DATA) {
            if(msg.data.id == ID_DONE) {
                timestamp = ltohl(msg.data.size);
                break;
            }
            fail_message(s, "invalid data message");
            goto fail;
        }
        len = ltohl(msg.data.size);
        if (len > buffer.size()) { // TODO: resize buffer?
            fail_message(s, "oversize data message");
            goto fail;
        }
        if (!ReadFdExactly(s, &buffer[0], len)) goto fail;

        if (fd < 0) continue;

        if (!WriteFdExactly(fd, &buffer[0], len)) {
            int saved_errno = errno;
            adb_close(fd);
            if (do_unlink) adb_unlink(path);
            fd = -1;
            errno = saved_errno;
            if (fail_errno(s)) return false;
        }
    }

    if(fd >= 0) {
        struct utimbuf u;
        adb_close(fd);
        selinux_android_restorecon(path, 0);
        u.actime = timestamp;
        u.modtime = timestamp;
        utime(path, &u);

        msg.status.id = ID_OKAY;
        msg.status.msglen = 0;
        if (!WriteFdExactly(s, &msg.status, sizeof(msg.status))) return false;
    }
    return true;

fail:
    if (fd >= 0) adb_close(fd);
    if (do_unlink) adb_unlink(path);
    return false;
}

#if defined(_WIN32)
extern bool handle_send_link(int s, char *path, std::vector<char>& buffer) __attribute__((error("no symlinks on Windows")));
#else
static bool handle_send_link(int s, char *path, std::vector<char>& buffer) {
    syncmsg msg;
    unsigned int len;
    int ret;

    if (!ReadFdExactly(s, &msg.data, sizeof(msg.data))) return false;

    if (msg.data.id != ID_DATA) {
        fail_message(s, "invalid data message: expected ID_DATA");
        return false;
    }

    len = ltohl(msg.data.size);
    if (len > buffer.size()) { // TODO: resize buffer?
        fail_message(s, "oversize data message");
        return false;
    }
    if (!ReadFdExactly(s, &buffer[0], len)) return false;

    ret = symlink(&buffer[0], path);
    if (ret && errno == ENOENT) {
        if (!secure_mkdirs(path)) {
            fail_errno(s);
            return false;
        }
        ret = symlink(&buffer[0], path);
    }
    if (ret) {
        fail_errno(s);
        return false;
    }

    if (!ReadFdExactly(s, &msg.data, sizeof(msg.data))) return false;

    if (msg.data.id == ID_DONE) {
        msg.status.id = ID_OKAY;
        msg.status.msglen = 0;
        if (!WriteFdExactly(s, &msg.status, sizeof(msg.status))) return false;
    } else {
        fail_message(s, "invalid data message: expected ID_DONE");
        return false;
    }

    return true;
}
#endif

static bool do_send(int s, char* path, std::vector<char>& buffer) {
    unsigned int mode;
    bool is_link = false;
    bool do_unlink;

    char* tmp = strrchr(path,',');
    if(tmp) {
        *tmp = 0;
        errno = 0;
        mode = strtoul(tmp + 1, NULL, 0);
        is_link = S_ISLNK((mode_t) mode);
        mode &= 0777;
    }
    if(!tmp || errno) {
        mode = 0644;
        is_link = 0;
        do_unlink = true;
    } else {
        struct stat st;
        /* Don't delete files before copying if they are not "regular" */
        do_unlink = lstat(path, &st) || S_ISREG(st.st_mode) || S_ISLNK(st.st_mode);
        if (do_unlink) {
            adb_unlink(path);
        }
    }

    if (is_link) {
        return handle_send_link(s, path, buffer);
    }

    uid_t uid = -1;
    gid_t gid = -1;
    uint64_t cap = 0;

    /* copy user permission bits to "group" and "other" permissions */
    mode |= ((mode >> 3) & 0070);
    mode |= ((mode >> 3) & 0007);

    tmp = path;
    if(*tmp == '/') {
        tmp++;
    }
    if (should_use_fs_config(path)) {
        fs_config(tmp, 0, &uid, &gid, &mode, &cap);
    }
    return handle_send_file(s, path, uid, gid, mode, buffer, do_unlink);
}

static bool do_recv(int s, const char* path, std::vector<char>& buffer) {
    int fd = adb_open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (fail_errno(s)) return false;
        return true;
    }

    syncmsg msg;
    msg.data.id = ID_DATA;
    while (true) {
        int r = adb_read(fd, &buffer[0], buffer.size());
        if (r <= 0) {
            if (r == 0) break;
            if (errno == EINTR) continue;
            bool status = fail_errno(s);
            adb_close(fd);
            return status;
        }
        msg.data.size = htoll(r);
        if (!WriteFdExactly(s, &msg.data, sizeof(msg.data)) || !WriteFdExactly(s, &buffer[0], r)) {
            adb_close(fd);
            return false;
        }
    }

    adb_close(fd);

    msg.data.id = ID_DONE;
    msg.data.size = 0;
    return WriteFdExactly(s, &msg.data, sizeof(msg.data));
}

static bool handle_sync_command(int fd, std::vector<char>& buffer) {
    D("sync: waiting for request\n");

    SyncRequest request;
    if (!ReadFdExactly(fd, &request, sizeof(request))) {
        fail_message(fd, "command read failure");
        return false;
    }
    size_t path_length = ltohl(request.path_length);
    if (path_length > 1024) {
        fail_message(fd, "path too long");
        return false;
    }
    char name[1025];
    if (!ReadFdExactly(fd, name, path_length)) {
        fail_message(fd, "filename read failure");
        return false;
    }
    name[path_length] = 0;

    const char* id = reinterpret_cast<const char*>(&request.id);
    D("sync: '%.4s' '%s'\n", id, name);

    switch (request.id) {
      case ID_STAT:
        if (!do_stat(fd, name)) return false;
        break;
      case ID_LIST:
        if (!do_list(fd, name)) return false;
        break;
      case ID_SEND:
        if (!do_send(fd, name, buffer)) return false;
        break;
      case ID_RECV:
        if (!do_recv(fd, name, buffer)) return false;
        break;
      case ID_QUIT:
        return false;
      default:
        fail_message(fd, android::base::StringPrintf("unknown command '%.4s' (%08x)",
                                                     id, request.id));
        return false;
    }

    return true;
}

void file_sync_service(int fd, void* cookie) {
    std::vector<char> buffer(SYNC_DATA_MAX);

    while (handle_sync_command(fd, buffer)) {
    }

    D("sync: done\n");
    adb_close(fd);
}

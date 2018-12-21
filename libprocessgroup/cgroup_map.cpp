/*
 *  Copyright 2018 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "libprocessgroup"

#include <cgroup_map.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <utils.h>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>

#include <cutils/android_filesystem_config.h>

using android::base::GetBoolProperty;
using android::base::StringPrintf;

#define CGROUP_PROCS_FILE "/cgroup.procs"
#define CGROUP_TASKS_FILE "/tasks"
#define CGROUP_TASKS_FILE_V2 "/cgroup.tasks"

#define CGROUPS_DB_FILE "/dev/cgroup.rc"

/* /proc/mounts parsing constants */
#define FILE_PROC_MOUNTS "/proc/mounts"

#define MOUNTS_LINE_ENTRY_MAXCNT 15

#define MOUNTS_CGROUP_TAG "cgroup"
#define MOUNTS_CGROUP2_TAG "cgroup2"

#define MOUNTS_LINE_ENTRY_CGPATH 1
#define MOUNTS_LINE_ENTRY_CGTAG 2
#define MOUNTS_LINE_ENTRY_CGTYPE 8

/* cgroup map file constants */
#define FILE_VERSION_1 1
#define FILE_CURR_VERSION FILE_VERSION_1

#define CGROUP_NAME_BUF_SZ 16
#define CGROUP_PATH_BUF_SZ 32

#define CGROUPV2_DEF_NAME "cgroup2"

struct cgroup_controller {
    uint32_t version;
    char name[CGROUP_NAME_BUF_SZ];
    char path[CGROUP_PATH_BUF_SZ];
};

struct CgroupFile {
    uint32_t version;
    uint32_t cntrl_count;
    // not storing struct timespec for modification time
    // directly because of variable size (8 or 16 bytes)
    uint32_t mod_secs;
    uint32_t mod_nsecs;
    struct cgroup_controller cntrl[];
};

CgroupMap CgroupMap::instance;
std::once_flag CgroupMap::initFlag;

CgroupMap::~CgroupMap() {
    if (cg_file_data) {
        munmap(cg_file_data, cg_file_size);
        cg_file_data = NULL;
        cg_file_size = 0;
    }
}

int CgroupMap::Write(const std::map<std::string,
                        struct cgroup_controller>& cd_detected) {
    int ret;
    struct CgroupFile fl;
    int fd;
    struct timespec curr_tm;

    fd = open(CGROUPS_DB_FILE, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC,
        S_IRUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
        PLOG(ERROR) << "Error in open(): " << strerror(errno);
        return -1;
    }

    fl.version = FILE_CURR_VERSION;
    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &curr_tm) != 0) {
        PLOG(ERROR) << "Failed to get current time";
        fl.mod_secs = 0;
        fl.mod_nsecs = 0;
    } else {
        fl.mod_secs = curr_tm.tv_sec;
        fl.mod_nsecs = curr_tm.tv_nsec;
    }
    fl.cntrl_count = cd_detected.size();
    ret = TEMP_FAILURE_RETRY(write(fd, &fl, sizeof(fl)));
    if (ret < 0) {
        PLOG(ERROR) << "Error in write(): " << strerror(errno);
        close(fd);
        return ret;
    }

    for (auto it = cd_detected.begin(); it != cd_detected.end(); ++it) {
        ret = TEMP_FAILURE_RETRY(write(fd, &(it->second), sizeof(it->second)));
        if (ret < 0) {
            PLOG(ERROR) << "Error in write(): " << strerror(errno);
            close(fd);
            return ret;
        }
    }

    close(fd);
    Chown(CGROUPS_DB_FILE, AID_SYSTEM, AID_SYSTEM);

    return 0;
}

void CgroupMap::Init() {
    int ret = instance.Load();
    if (ret < 0) {
        PLOG(ERROR) << "CgroupMap::Load called for ["
                    << getpid() << "] returns " << ret;
    }
}

int CgroupMap::Load() {
    struct stat sb;
    int fd;

    if (cg_file_data) {
        // Data already initialized
        return 0;
    }

    fd = open(CGROUPS_DB_FILE, O_CLOEXEC, O_RDONLY);
    if (fd < 0) {
        PLOG(ERROR) << "Error in open: " << strerror(errno);
        return -1;
    }

    if (fstat(fd, &sb) < 0) {
        PLOG(ERROR) << "Error in fstat: " << strerror(errno);
        close(fd);
        return -1;
    }

    cg_file_size = sb.st_size;

    cg_file_data = (char *)mmap(NULL, cg_file_size, PROT_READ, MAP_SHARED, fd, 0);
    if (cg_file_data == MAP_FAILED) {
        PLOG(ERROR) << "Error in mmap: " << strerror(errno);
        close(fd);
        return -1;
    }

    close(fd);
    //Print();

    return 0;
}

void CgroupMap::Print() {
    struct CgroupFile *fl = (struct CgroupFile *)cg_file_data;
    struct cgroup_controller *controller = (struct cgroup_controller *)
        (cg_file_data + sizeof(struct CgroupFile));

    LOG(INFO) << "File version = " << fl->version;
    LOG(INFO) << "File last update sec = " << fl->mod_secs;
    LOG(INFO) << "File last update nsec = " << fl->mod_nsecs;
    LOG(INFO) << "File cntrl_count = " << fl->cntrl_count;

    LOG(INFO) << "Detected cgroups:";
    for (int i = 0; i < fl->cntrl_count; i++, controller++) {
        LOG(INFO) << "\t" << controller->name
            << " ver " << controller->version
            << " path " <<  controller->path;

    }
}

bool CgroupMap::IsCgroupSystem(const std::string& system) {
    return (system == "cgroup" ||
            system == "cgroup2" ||
            system == "cpuset");
}

int CgroupMap::Detect() {
    FILE *fp;
    char line[256];
    char *tokens[MOUNTS_LINE_ENTRY_MAXCNT];
    struct cgroup_controller controller;
    std::string cg2_path;
    std::map<std::string, struct cgroup_controller> cd_detected;

    fp = fopen(FILE_PROC_MOUNTS, "r");
    if (!fp) {
        PLOG(ERROR) << "Cgroups detection failed to open "
                    << FILE_PROC_MOUNTS << ": " << strerror(errno);
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, MOUNTS_CGROUP_TAG) ||
            strstr(line, MOUNTS_CGROUP2_TAG)) {
            int cnt = GetTokens(line, " ,", tokens, MOUNTS_LINE_ENTRY_MAXCNT);
            if (cnt >= MOUNTS_LINE_ENTRY_CGTAG) {
                if (strcmp(tokens[MOUNTS_LINE_ENTRY_CGTAG],
                        MOUNTS_CGROUP_TAG) == 0 &&
                        cnt > MOUNTS_LINE_ENTRY_CGTYPE) {
                    controller.version = 1;
                    strncpy(controller.name, tokens[MOUNTS_LINE_ENTRY_CGTYPE],
                        sizeof(controller.name) - 1);
                    controller.name[sizeof(controller.name) - 1] = '\0';
                    strncpy(controller.path, tokens[MOUNTS_LINE_ENTRY_CGPATH],
                        sizeof(controller.path) - 1);
                    controller.path[sizeof(controller.path) - 1] = '\0';
                    cd_detected[controller.name] = controller;
                } else if (strcmp(tokens[MOUNTS_LINE_ENTRY_CGTAG],
                                  MOUNTS_CGROUP2_TAG) == 0) {
                    cg2_path = tokens[MOUNTS_LINE_ENTRY_CGPATH];
                }
            }
        }
    }

    fclose(fp);

    if (!cg2_path.empty()) {
        /* Add cgroup v2 as a separate controller */
        controller.version = 2;
        strncpy(controller.name, CGROUPV2_DEF_NAME, sizeof(controller.name) - 1);
        controller.name[sizeof(controller.name) - 1] = '\0';
        strncpy(controller.path, cg2_path.c_str(), sizeof(controller.path) - 1);
        controller.path[sizeof(controller.path) - 1] = '\0';
        cd_detected[controller.name] = controller;

        /* Find out available cgroup v2 controllers */
        fp = fopen((cg2_path + "/cgroup.controllers").c_str(), "r");
        if (!fp) {
            PLOG(ERROR) << "Cgroups detection failed to open "
                        << cg2_path << "/cgroup.controllers" << ": "
                        << strerror(errno);
            return -1;
        }

        while (fgets(line, sizeof(line), fp) != NULL) {
            char *pos;

            controller.version = 2;
            if ((pos = strchr(line, '\n')) != NULL) {
                *pos = '\0';
            }
            strncpy(controller.name, line, sizeof(controller.name) - 1);
            controller.name[sizeof(controller.name) - 1] = '\0';
            strncpy(controller.path, cg2_path.c_str(), sizeof(controller.path) - 1);
            controller.path[sizeof(controller.path) - 1] = '\0';
            cd_detected[controller.name] = controller;
        }

        fclose(fp);
    }

    return Write(cd_detected);
}

const struct cgroup_controller *CgroupMap::FindController(const std::string& name) const {
    struct CgroupFile *fl;
    struct cgroup_controller *controller;

    if (!cg_file_data) {
        return NULL;
    }

    fl = (struct CgroupFile *)cg_file_data;
    controller = (struct cgroup_controller *)(cg_file_data + sizeof(struct CgroupFile));
    for (int i = 0; i < fl->cntrl_count; i++, controller++) {
        if (name == controller->name) {
            return controller;
        }
    }
    return NULL;
}

std::string CgroupMap::GetTasksFilePath(const struct cgroup_controller *controller,
                                        const std::string& path) {
    std::string tasks_path = controller->path;

    if (!path.empty()) {
        tasks_path += "/" + path;
    }
    return (controller->version == 1) ?
        tasks_path + CGROUP_TASKS_FILE :
        tasks_path + CGROUP_TASKS_FILE_V2;
}

int CgroupMap::GetProcessGroup(const struct cgroup_controller *controller,
                               int tid, std::string& group) {
    std::string file_name = StringPrintf("/proc/%d/cgroup", tid);
    std::string cg_tag = StringPrintf(":%s:", controller->name);
    char buf[256];
    char *pos_start, *pos_end;
    int fd;

    fd = open(file_name.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        return -errno;
    }
    ssize_t r = TEMP_FAILURE_RETRY(read(fd, buf, sizeof(buf) - 1));
    if (r == -1) {
        close(fd);
        return -errno;
    }
    buf[r] = '\0';
    close(fd);

    pos_start = strstr(buf, cg_tag.c_str());
    if (pos_start == nullptr) {
        return -1;
    }

    pos_start += cg_tag.length() + 1; // skip '/'
    pos_end = strchr(pos_start, '\n');
    if (pos_end != nullptr) {
        *pos_end = '\0';
    }

    group = pos_start;
    return 0;
}

const char *CgroupMap::GetControllerName(const struct cgroup_controller *controller) {
    return controller->name;
}

const char *CgroupMap::GetControllerPath(const struct cgroup_controller *controller) {
    return controller->path;
}

std::string CgroupMap::GetProcsFilePath(const struct cgroup_controller *controller,
                                  const std::string& path, uid_t uid, pid_t pid) {
    std::string procs_path = ExpandAppDependentPath(
        GetControllerPath(controller), path, uid, pid);
    return procs_path + CGROUP_PROCS_FILE;
}

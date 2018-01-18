/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <memory>
#include <unordered_set>

#include <android-base/macros.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/ashmem.h>
#include <gtest/gtest.h>

// not so much a speedup, as a way of annotating impossible/unexpected paths
#ifndef __predict_false  // defined in Android controlled sys/cdefs.h
#define __predict_false(exp) __builtin_expect((exp) != 0, 0)
#endif

using android::base::StartsWith;
using android::base::unique_fd;

void TestCreateRegion(size_t size, unique_fd &fd, int prot) {
    fd = unique_fd(ashmem_create_region(nullptr, size));
    ASSERT_TRUE(fd >= 0);
    ASSERT_TRUE(ashmem_valid(fd));
    ASSERT_EQ(size, static_cast<size_t>(ashmem_get_size_region(fd)));
    ASSERT_EQ(0, ashmem_set_prot_region(fd, prot));
}

void TestMmap(const unique_fd& fd, size_t size, int prot, void** region, off_t off = 0) {
    ASSERT_TRUE(fd >= 0);
    ASSERT_TRUE(ashmem_valid(fd));
    *region = mmap(nullptr, size, prot, MAP_SHARED, fd, off);
    ASSERT_NE(MAP_FAILED, *region);
}

void TestProtDenied(const unique_fd &fd, size_t size, int prot) {
    ASSERT_TRUE(fd >= 0);
    ASSERT_TRUE(ashmem_valid(fd));
    EXPECT_EQ(MAP_FAILED, mmap(nullptr, size, prot, MAP_SHARED, fd, 0));
}

void TestProtIs(const unique_fd& fd, int prot) {
    ASSERT_TRUE(fd >= 0);
    ASSERT_TRUE(ashmem_valid(fd));
    EXPECT_EQ(prot, ioctl(fd, ASHMEM_GET_PROT_MASK));
}

void FillData(uint8_t* data, size_t dataLen) {
    for (size_t i = 0; i < dataLen; i++) {
        data[i] = i & 0xFF;
    }
}

TEST(AshmemTest, BasicTest) {
    constexpr size_t size = PAGE_SIZE;
    uint8_t data[size];
    FillData(data, size);

    unique_fd fd;
    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE));

    void *region1;
    ASSERT_NO_FATAL_FAILURE(TestMmap(fd, size, PROT_READ | PROT_WRITE, &region1));

    memcpy(region1, &data, size);
    ASSERT_EQ(0, memcmp(region1, &data, size));

    EXPECT_EQ(0, munmap(region1, size));

    void *region2;
    ASSERT_NO_FATAL_FAILURE(TestMmap(fd, size, PROT_READ, &region2));
    ASSERT_EQ(0, memcmp(region2, &data, size));
    EXPECT_EQ(0, munmap(region2, size));
}

TEST(AshmemTest, ForkTest) {
    constexpr size_t size = PAGE_SIZE;
    uint8_t data[size];
    FillData(data, size);

    unique_fd fd;
    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE));

    void *region1;
    ASSERT_NO_FATAL_FAILURE(TestMmap(fd, size, PROT_READ | PROT_WRITE, &region1));

    memcpy(region1, &data, size);
    ASSERT_EQ(0, memcmp(region1, &data, size));
    EXPECT_EQ(0, munmap(region1, size));

    ASSERT_EXIT(
        {
            if (!ashmem_valid(fd)) {
                _exit(3);
            }
            void* region2 = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (region2 == MAP_FAILED) {
                _exit(1);
            }
            if (memcmp(region2, &data, size) != 0) {
                _exit(2);
            }
            memset(region2, 0, size);
            munmap(region2, size);
            _exit(0);
        },
        ::testing::ExitedWithCode(0), "");

    memset(&data, 0, size);
    void *region2;
    ASSERT_NO_FATAL_FAILURE(TestMmap(fd, size, PROT_READ | PROT_WRITE, &region2));
    ASSERT_EQ(0, memcmp(region2, &data, size));
    EXPECT_EQ(0, munmap(region2, size));
}

TEST(AshmemTest, FileOperationsTest) {
    unique_fd fd;
    void* region;

    // Allocate a 4-page buffer, but leave page-sized holes on either side
    constexpr size_t size = PAGE_SIZE * 4;
    constexpr size_t dataSize = PAGE_SIZE * 2;
    constexpr size_t holeSize = PAGE_SIZE;
    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE));
    ASSERT_NO_FATAL_FAILURE(TestMmap(fd, dataSize, PROT_READ | PROT_WRITE, &region, holeSize));

    uint8_t data[dataSize];
    FillData(data, dataSize);
    memcpy(region, data, dataSize);

    constexpr off_t dataStart = holeSize;
    constexpr off_t dataEnd = dataStart + dataSize;

    // The sequence of seeks below looks something like this:
    //
    // [    ][data][data][    ]
    // --^                          lseek(99, SEEK_SET)
    //   ------^                    lseek(dataStart, SEEK_CUR)
    // ------^                      lseek(0, SEEK_DATA)
    //       ------------^          lseek(dataStart, SEEK_HOLE)
    //                      ^--     lseek(-99, SEEK_END)
    //                ^------       lseek(-dataStart, SEEK_CUR)
    const struct {
        // lseek() parameters
        off_t offset;
        int whence;
        // Expected lseek() return value
        off_t ret;
    } seeks[] = {
        {99, SEEK_SET, 99},         {dataStart, SEEK_CUR, dataStart + 99},
        {0, SEEK_DATA, dataStart},  {dataStart, SEEK_HOLE, dataEnd},
        {-99, SEEK_END, size - 99}, {-dataStart, SEEK_CUR, dataEnd - 99},
    };
    for (const auto& cfg : seeks) {
        errno = 0;
        ASSERT_TRUE(ashmem_valid(fd));
        auto off = lseek(fd, cfg.offset, cfg.whence);
        ASSERT_EQ(cfg.ret, off) << "lseek(" << cfg.offset << ", " << cfg.whence << ") failed"
                                << (errno ? ": " : "") << (errno ? strerror(errno) : "");

        if (off >= dataStart && off < dataEnd) {
            off_t dataOff = off - dataStart;
            ssize_t readSize = dataSize - dataOff;
            uint8_t buf[readSize];

            ASSERT_EQ(readSize, TEMP_FAILURE_RETRY(read(fd, buf, readSize)));
            EXPECT_EQ(0, memcmp(buf, data + dataOff, readSize));
        }
    }

    EXPECT_EQ(0, munmap(region, dataSize));
}

TEST(AshmemTest, ProtTest) {
    unique_fd fd;
    constexpr size_t size = PAGE_SIZE;
    void *region;

    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ));
    TestProtDenied(fd, size, PROT_WRITE);
    TestProtIs(fd, PROT_READ);
    ASSERT_NO_FATAL_FAILURE(TestMmap(fd, size, PROT_READ, &region));
    EXPECT_EQ(0, munmap(region, size));

    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_WRITE));
    TestProtDenied(fd, size, PROT_READ);
    TestProtIs(fd, PROT_WRITE);
    ASSERT_NO_FATAL_FAILURE(TestMmap(fd, size, PROT_WRITE, &region));
    EXPECT_EQ(0, munmap(region, size));

    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE));
    TestProtIs(fd, PROT_READ | PROT_WRITE);
    ASSERT_EQ(0, ashmem_set_prot_region(fd, PROT_READ));
    errno = 0;
    ASSERT_EQ(-1, ashmem_set_prot_region(fd, PROT_READ | PROT_WRITE))
        << "kernel shouldn't allow adding protection bits";
    EXPECT_EQ(EINVAL, errno);
    TestProtIs(fd, PROT_READ);
    TestProtDenied(fd, size, PROT_WRITE);
}

TEST(AshmemTest, ForkProtTest) {
    unique_fd fd;
    constexpr size_t size = PAGE_SIZE;

    int protFlags[] = { PROT_READ, PROT_WRITE };
    for (size_t i = 0; i < arraysize(protFlags); i++) {
        ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE));
        ASSERT_EXIT(
            {
                if (!ashmem_valid(fd)) {
                    _exit(3);
                } else if (ashmem_set_prot_region(fd, protFlags[i]) >= 0) {
                    _exit(0);
                } else {
                    _exit(1);
                }
            },
            ::testing::ExitedWithCode(0), "");
        ASSERT_NO_FATAL_FAILURE(TestProtDenied(fd, size, protFlags[1-i]));
    }
}

TEST(AshmemTest, ForkMultiRegionTest) {
    constexpr size_t size = PAGE_SIZE;
    uint8_t data[size];
    FillData(data, size);

    constexpr int nRegions = 16;
    unique_fd fd[nRegions];
    for (int i = 0; i < nRegions; i++) {
        ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd[i], PROT_READ | PROT_WRITE));
        void *region;
        ASSERT_NO_FATAL_FAILURE(TestMmap(fd[i], size, PROT_READ | PROT_WRITE, &region));
        memcpy(region, &data, size);
        ASSERT_EQ(0, memcmp(region, &data, size));
        EXPECT_EQ(0, munmap(region, size));
    }

    ASSERT_EXIT({
        for (int i = 0; i < nRegions; i++) {
            if (!ashmem_valid(fd[i])) {
                _exit(3);
            }
            void *region = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd[i], 0);
            if (region == MAP_FAILED) {
                _exit(1);
            }
            if (memcmp(region, &data, size) != 0) {
                munmap(region, size);
                _exit(2);
            }
            memset(region, 0, size);
            munmap(region, size);
        }
        _exit(0);
    }, ::testing::ExitedWithCode(0), "");

    memset(&data, 0, size);
    for (int i = 0; i < nRegions; i++) {
        void *region;
        ASSERT_NO_FATAL_FAILURE(TestMmap(fd[i], size, PROT_READ | PROT_WRITE, &region));
        ASSERT_EQ(0, memcmp(region, &data, size));
        EXPECT_EQ(0, munmap(region, size));
    }
}

namespace {

constexpr size_t maxLineWidth = 80;
constexpr char infoPrefix[] = "\r[   INFO   ] ";
constexpr char failedPrefix[] = "[  FAILED  ] ";

// Report name we intent to operate on just in case kernel panics
// on a false positive and sends an ill advised ioctl to that node.
void reportName(const std::string& name) {
    size_t len = maxLineWidth - 1 - strlen(infoPrefix + 1);
    ssize_t pos = name.size() - len;
    std::string prefix(infoPrefix);
    if (pos > 0) {
        static constexpr char elipse[] = "...";
        pos += strlen(elipse);
        len -= strlen(elipse);
        prefix += elipse;
    } else {
        pos = 0;
    }
    std::cerr << prefix << std::setw(len + 1) << std::left << name.substr(pos, len) << std::flush;
    usleep(20000);  // pause to flush before possible kernel panic
}

void clearName() {
    std::cerr << '\r' << std::setw(maxLineWidth) << std::right << '\r' << std::flush;
}

void caught_signal(int /* signum */) {}

void checkAshmem(std::unordered_set<std::string>& checked, const std::string& name) {
    if (checked.find(name) != checked.end()) {
        return;
    }
    checked.insert(name);

    // Try to open it as a socket first
    unique_fd fd(-1);
    struct sockaddr_un un;
    int errorNumber = 0;
    if (name.size() <= sizeof(un.sun_path)) {
        for (auto&& t : {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET, SOCK_RAW, SOCK_RDM}) {
            fd.reset(socket(PF_UNIX, t | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
            if (__predict_false(fd < 0)) {
                errorNumber = errno;
                continue;
            }
            memset(&un, 0, sizeof(struct sockaddr_un));
            un.sun_family = AF_UNIX;
            strncpy(un.sun_path, name.c_str(), sizeof(un.sun_path));
            if (!TEMP_FAILURE_RETRY(connect(fd, (struct sockaddr*)&un, sizeof(struct sockaddr_un)))) {
                break;
            }
            errorNumber = errno;
            fd.reset(-1);
            if (errorNumber != EPROTOTYPE) {
                break;
            }
            // if connection type does not match other side, then try another
        }
    }
    EXPECT_TRUE((fd >= 0) || !StartsWith(name, "/dev/socket/"))
        << failedPrefix << name << " " << strerror(errorNumber);

    if (fd < 0) {
        // protect ourselves from bad device drivers in the kernel
        struct sigaction ignore, old_sigaction;
        memset(&ignore, 0, sizeof(ignore));
        ignore.sa_handler = caught_signal;
        sigemptyset(&ignore.sa_mask);
        sigaction(SIGALRM, &ignore, &old_sigaction);
        unsigned int old_alarm;
#ifdef __linux__
        old_alarm = 1;
#else
        old_alarm = 2;
#endif
        old_alarm = alarm(old_alarm);

        fd.reset(open(name.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK));

        alarm(old_alarm);
        sigaction(SIGALRM, &old_sigaction, nullptr);
    }

    if ((fd < 0) || !ashmem_valid(fd)) {
        return;
    }

    reportName(name);

    EXPECT_GT(ashmem_get_size_region(fd), (name == "/dev/ashmem") ? -1 : 0) << failedPrefix << name;
}

void recurseAshmem(std::unordered_set<std::string>& checked, const std::string& directory) {
    std::unique_ptr<DIR, decltype(&closedir)> d(opendir(directory.c_str()), closedir);
    if (d.get() == nullptr) {
        return;
    }

    dirent* dp;
    while ((dp = readdir(d.get())) != nullptr) {
        if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, "..")) {
            continue;
        }

        std::string name = directory;
        name += dp->d_name;
        if (__predict_false(dp->d_type == DT_UNKNOWN)) {
            struct stat st;
            if (!lstat(name.c_str(), &st) && (st.st_mode & S_IFDIR)) {
                dp->d_type = DT_DIR;
            }
        }
        if (dp->d_type == DT_DIR) {
            name += "/";
            recurseAshmem(checked, name);
            continue;
        }
        checkAshmem(checked, name);
    }
}

}  // namespace

TEST(AshmemTest, scan_valid) {
    //
    // Intent is to hit all files, some of which may be named ipc nodes or
    // drivers that respond to an ioctl() call.  Scaling is better, and more
    // focussed, if it hits all open files, active vendor specific nodes.
    //
    static constexpr char procdir[] = "/proc/";
    std::unique_ptr<DIR, decltype(&closedir)> d(opendir(procdir), closedir);

    std::unordered_set<std::string> checked;
    dirent* dp;
    if (d.get() != nullptr) {
        while ((dp = readdir(d.get())) != nullptr) {
            if (!isdigit(dp->d_name[0])) {
                continue;
            }
            std::string fddir = procdir;
            fddir += dp->d_name;
            if (__predict_false(dp->d_type == DT_UNKNOWN)) {
                struct stat st;
                if (lstat(fddir.c_str(), &st) || !(st.st_mode & S_IFDIR)) {
                    continue;
                }
            } else if (dp->d_type != DT_DIR) {
                continue;
            }
            fddir += "/fd/";
            std::unique_ptr<DIR, decltype(&closedir)> fdd(opendir(fddir.c_str()), closedir);
            if (fdd.get() == nullptr) {
                continue;
            }
            while ((dp = readdir(fdd.get())) != nullptr) {
                if (!isdigit(dp->d_name[0])) {
                    continue;
                }
                std::string name = fddir + "/" + dp->d_name;
                if (__predict_false(dp->d_type == DT_UNKNOWN)) {
                    struct stat st;
                    if (lstat(name.c_str(), &st) || !(st.st_mode & S_IFLNK)) {
                        continue;
                    }
                } else if (dp->d_type != DT_LNK) {
                    continue;
                }
                char buf[PATH_MAX];
                ssize_t ret = TEMP_FAILURE_RETRY(readlink(name.c_str(), buf, sizeof(buf)));
                // use _real_ path to node
                if ((ret > 0) && (static_cast<size_t>(ret) < sizeof(buf))) {
                    name = std::string(buf, ret);
                }

                checkAshmem(checked, name);
            }
        }
        d.reset(nullptr);
    }

    // Let's abuse the device directory too, where all drivers and sockets are.
    recurseAshmem(checked, "/dev/");

    // Others?

    // Report
    clearName();
    std::cerr << infoPrefix << checked.size() << " files checked\n";
}

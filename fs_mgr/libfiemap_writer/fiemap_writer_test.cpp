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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <libdm/loop_control.h>

#include <libfiemap_writer/fiemap_writer.h>

using namespace std;
using namespace android::fiemap_writer;
using unique_fd = android::base::unique_fd;

std::string testfile = "";
std::string testbdev = "";
uint64_t testfile_size = 536870912;  // default of 512MiB

TEST(FiemapWriter, CreateImpossiblyLargeFile) {
    FiemapWriter fwriter;
    // Try creating a file of size ~100TB but aligned to
    // 512 byte to make sure block alignment tests don't
    // fail.
    EXPECT_FALSE(fwriter.Create(testfile, 1099511627997184));
    EXPECT_EQ(access(testfile.c_str(), F_OK), -1);
    EXPECT_EQ(errno, ENOENT);
}

TEST(FiemapWriter, CreateUnalignedFile) {
    FiemapWriter fwriter;
    // Try creating a file of size 4097 bytes which is guaranteed
    // to be unaligned to all known block sizes. The creation must
    // fail.
    EXPECT_FALSE(fwriter.Create(testfile, 4097));
    EXPECT_EQ(access(testfile.c_str(), F_OK), -1);
    EXPECT_EQ(errno, ENOENT);
}

TEST(FiemapWriter, DoubleCreate) {
    FiemapWriter fwriter;

    EXPECT_TRUE(fwriter.Create(testfile, 4096));
    // Trying to create again must fail with the same object.
    EXPECT_FALSE(fwriter.Create(testfile, 4096));
    EXPECT_EQ(access(testfile.c_str(), F_OK), 0);
}

TEST(FiemapWriter, CheckFilePath) {
    FiemapWriter fwriter;

    EXPECT_TRUE(fwriter.Create(testfile, 4096));
    EXPECT_EQ(fwriter.size(), 4096);
    EXPECT_EQ(fwriter.file_path(), testfile);
    EXPECT_EQ(access(testfile.c_str(), F_OK), 0);
}

TEST(FiemapWriter, CheckBlockDevicePath) {
    FiemapWriter fwriter;

    EXPECT_TRUE(fwriter.Create(testfile, 4096));
    EXPECT_EQ(fwriter.size(), 4096);
    EXPECT_EQ(fwriter.bdev_path(), testbdev);
}

TEST(FiemapWriter, CheckFileCreated) {
    FiemapWriter fwriter;

    EXPECT_TRUE(fwriter.Create(testfile, 32768));
    unique_fd fd(open(testfile.c_str(), O_RDONLY));
    EXPECT_GT(fd, -1);
}

TEST(FiemapWriter, CheckFileSizeActual) {
    FiemapWriter fwriter;

    EXPECT_TRUE(fwriter.Create(testfile, testfile_size));

    struct stat sb;
    ASSERT_EQ(stat(testfile.c_str(), &sb), 0);
    EXPECT_EQ(sb.st_size, testfile_size);
}

TEST(FiemapWriter, CheckFileExtents) {
    FiemapWriter fwriter;

    EXPECT_TRUE(fwriter.Create(testfile, testfile_size));
    EXPECT_GT(fwriter.Fiemap().size(), 0);
}

TEST(FiemapWriter, CheckWriteError) {
    FiemapWriter fwriter;
    EXPECT_TRUE(fwriter.Create(testfile, testfile_size));

    // prepare buffer for writing the patter - 0xa0
    uint64_t blocksize = fwriter.BlockSize();
    auto buffer = std::unique_ptr<void, decltype(&free)>(calloc(1, blocksize), free);
    ASSERT_NE(buffer, nullptr);
    memset(buffer.get(), 0xa0, blocksize);

    uint8_t* p = static_cast<uint8_t*>(buffer.get());
    for (off64_t off = 0; off < testfile_size; off += blocksize, p += blocksize) {
        EXPECT_TRUE(fwriter.Write(off, p, blocksize));
    }

    EXPECT_TRUE(fwriter.Flush());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (argc <= 2) {
        cerr << "Filepath with its bdev path must be provided as follows:" << endl;
        cerr << "  $ fiemap_writer_test <path to file> </dev/block/XXXX" << endl;
        cerr << "  where, /dev/block/XXX is the block device where the file resides" << endl;
        exit(EXIT_FAILURE);
    }
    ::android::base::InitLogging(argv, ::android::base::StderrLogger);

    testfile = argv[1];
    testbdev = argv[2];
    if (argc > 3) {
        testfile_size = strtoull(argv[3], NULL, 0);
        if (testfile_size == ULLONG_MAX) {
            testfile_size = 512 * 1024 * 1024;
        }
    }

    return RUN_ALL_TESTS();
}

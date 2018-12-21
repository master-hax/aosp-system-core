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

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <string>

#include <libfiemap_writer/fiemap_writer.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>

using namespace std;
using namespace android::fiemap_writer;
using unique_fd = android::base::unique_fd;

std::string testfile = "";
std::string testbdev = "";

TEST(FiemapWriter, CreateImpossiblyLargeFile) {
    FiemapWriter fwriter;
    // Try creating a file of size ~100TB but aligned to
    // 512 byte to make sure block alignment tests don't
    // fail.
    EXPECT_EQ(false, fwriter.Create(testfile, 1099511627997184));
}

TEST(FiemapWriter, CreateUnalignedFile) {
    FiemapWriter fwriter;
    // Try creating a file of size 4097 bytes which is guaranteed
    // to be unaligned to all known block sizes. The creation must
    // fail.
    EXPECT_EQ(false, fwriter.Create(testfile, 4097));
}

TEST(FiemapWriter, DoubleCreate) {
    std::string fpath = "/data/local/tmp/fiemap_writer.raw";
    FiemapWriter fwriter;

    EXPECT_EQ(true, fwriter.Create(fpath, 4096));
    // Trying to create again must fail with the same object.
    EXPECT_EQ(false, fwriter.Create(fpath, 4096));
}

TEST(FiemapWriter, CheckFilePath) {
    std::string fpath = "/data/local/tmp/fiemap_writer.raw";
    FiemapWriter fwriter;

    fwriter.Create(fpath, 4096);
    EXPECT_EQ(4096, fwriter.size());
    EXPECT_EQ(fpath, fwriter.file_path());
}

TEST(FiemapWriter, CheckBlockDevicePath) {
    FiemapWriter fwriter;

    fwriter.Create(testfile, 4096);
    EXPECT_EQ(4096, fwriter.size());
    EXPECT_EQ(testbdev, fwriter.bdev_path());
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

    return RUN_ALL_TESTS();
}

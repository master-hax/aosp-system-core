/*
 * Copyright (C) 2017 The Android Open Source Project
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
#include <fstream>
#include <random>
#include <string>

#include <gtest/gtest.h>
#include <log/log.h>
#include <sparse/sparse.h>
#include "utils/FileMap.h"
#include "utils/List.h"

#include "sparse_format_test.h"

namespace android {

class SparseTest : public testing::Test {
  protected:
    static constexpr int kBlockSize = 4096;

    virtual void SetUp() {}
    virtual void TearDown() {
        for (std::string f : TestFiles) {
            unlink(f.c_str());
        }
        TestFiles.clear();
    }
    // Adds to the list of files to cleanup on TearDown. Dups are OK.
    void AddTestFile(std::string file) { TestFiles.push_back(file); }
    // Create a test file with FF's or use the byte offset as the value.
    void CreateTestFile(const char* filename, size_t size, bool counting) {
        unlink(filename);
        AddToFile(filename, size, counting, 0xFF);
    }
    // Create or append to a file, some padding with byte value "val"
    void AddPadding(const char* filename, size_t size, int val) {
        AddToFile(filename, size, false, val);
    }
    void AddToFile(const char* filename, size_t size, bool counting, int value) {
        char* buf = new char[kBlockSize];
        std::ofstream ofs(filename, std::ios::binary | std::ios::app);

        if (counting) {
            for (size_t i = 0; i < kBlockSize; i++) {
                buf[i] = (char)(i & 0xFF);
            }
        } else {
            memset(buf, value, (int)kBlockSize);
        }

        while (size) {
            size_t to_write = std::min(size, (size_t)kBlockSize);
            ofs.write(buf, to_write);
            size -= to_write;
        }
        AddTestFile(filename);
    }
    // UnsparseCmp compares two buffers, ignoring trailing zeroes in the larger buffer.
    // return 0 if buffers are equivalent, otherwise -1.
    int UnsparseCmp(void* p1, size_t s1, void* p2, size_t s2) {
        int validsize = std::min(s1, s2);

        int ret = memcmp(p1, p2, validsize);

        if (ret) return -1;
        char* tailp;
        size_t tailsz;
        if (s1 > s2) {
            tailsz = s1 - s2;
            tailp = static_cast<char*>(p1) + s2;
        } else if (s2 > s1) {
            tailsz = s2 - s1;
            tailp = static_cast<char*>(p2) + s1;
        } else {
            // They're the same size, and memcmp passed.
            return 0;
        }

        for (size_t i = 0; i < tailsz; i++) {
            if (tailp[i] != 0) {
                return -1;
            }
        }
        // The sizes are different, but tail of the larger one is just zero padding.
        return 0;
    }
    int UnsparseCmpFile(const char* file1, const char* file2) {
        size_t sz1 = GetFileSize(file1);
        size_t sz2 = GetFileSize(file2);
        int fd1 = open(file1, O_RDONLY);
        int fd2 = open(file2, O_RDONLY);
        FileMap map1, map2;
        map1.create(NULL, fd1, 0, sz1, true);
        map2.create(NULL, fd2, 0, sz2, true);
        return UnsparseCmp(map1.getDataPtr(), sz1, map2.getDataPtr(), sz2);
    }
    int RunSImg2Img(const char* in, const char* out) {
        int ret = Exec("simg2img", "simg2img", in, out, nullptr);
        AddTestFile(out);
        return ret;
    }
    int RunImg2SImg(const char* in, const char* out) {
        int ret = Exec("img2simg", "img2simg", in, out, nullptr);
        AddTestFile(out);
        return ret;
    }
    int RunAppend2SImg(const char* simg, const char* input) {
        return Exec("append2simg", "append2simg", simg, input, nullptr);
    }
    int ReadSparseHeader(const char* filename, sparse_header_t* sp) {
        int fd = open(filename, O_RDONLY);
        FileMap map;
        if (!map.create(NULL, fd, 0, sizeof(*sp), true)) {
            return -1;
        }
        memcpy(sp, map.getDataPtr(), sizeof(*sp));
        return 0;
    }
    size_t GetFileSize(const char* filename) {
        std::ifstream f(filename, std::ios::in | std::ios::binary);
        std::streampos begin = f.tellg();
        f.seekg(0, std::ios_base::end);
        std::streampos end = f.tellg();
        return end - begin;
    }

  private:
    int Exec(const char* exe, ...) {
        int pid = fork();
        int status;
        if (!pid) {
            int num_args = 0;
            va_list ap;
            va_start(ap, exe);
            while (va_arg(ap, char*) != nullptr) {
                num_args++;
            }
            num_args++;  // include nullptr
            va_end(ap);
            char** argv = new char*[num_args];
            va_start(ap, exe);
            for (int i = 0; i < num_args; i++) {
                argv[i] = va_arg(ap, char*);
            }
            execvp(exe, argv);
            ALOGE("Couldn't execute %s: %s", exe, strerror(errno));
            exit(-1);
        }
        TEMP_FAILURE_RETRY(waitpid(pid, &status, 0));
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        } else {
            return -1;
        }
    }
    List<std::string> TestFiles;
};

// test the test functions for sanity.
TEST_F(SparseTest, TestSparseTest) {
    CreateTestFile("test1", 8192, false);
    CreateTestFile("test2", 8192, false);
    AddPadding("test2", 4, 0);
    EXPECT_EQ(0, UnsparseCmpFile("test1", "test2"));

    CreateTestFile("test3", 8192, false);
    CreateTestFile("test4", 8196, false);
    EXPECT_EQ(0, !(UnsparseCmpFile("test3", "test4")));

    CreateTestFile("test5", 3, true);
    CreateTestFile("test6", 3, true);
    EXPECT_EQ(0, (UnsparseCmpFile("test5", "test6")));

    CreateTestFile("test7", 3, true);
    CreateTestFile("test8", 3, false);
    EXPECT_EQ(0, !(UnsparseCmpFile("test7", "test8")));
}

TEST_F(SparseTest, Img2SImg2ImgBasic) {
    CreateTestFile("a1", 1024 * 1024, true);
    EXPECT_EQ(0, RunImg2SImg("a1", "a1sparse"));
    EXPECT_EQ(0, RunSImg2Img("a1sparse", "a1unsparse"));
    EXPECT_EQ(0, UnsparseCmpFile("a1", "a1unsparse"));
}
TEST_F(SparseTest, Img2SImg2ImgOddSize) {
    CreateTestFile("a2", 1024 * 1024, true);
    AddPadding("a2", 1, 0);
    EXPECT_EQ(0, RunImg2SImg("a2", "a2sparse"));
    EXPECT_EQ(0, RunSImg2Img("a2sparse", "a2unsparse"));
    EXPECT_EQ(0, UnsparseCmpFile("a2", "a2unsparse"));

    CreateTestFile("a3", 1024 * 1024, true);
    AddPadding("a3", kBlockSize - 1, 0);
    EXPECT_EQ(0, RunImg2SImg("a3", "a3sparse"));
    EXPECT_EQ(0, RunSImg2Img("a3sparse", "a3unsparse"));
    EXPECT_EQ(0, UnsparseCmpFile("a3", "a3unsparse"));
}
TEST_F(SparseTest, SImgHeader) {
    size_t testsize = 1024 * 1024 + 1;
    CreateTestFile("a1", testsize, true);
    EXPECT_EQ(0, RunImg2SImg("a1", "a1sparse"));
    sparse_header_t header;
    EXPECT_EQ(0, ReadSparseHeader("a1sparse", &header));
    EXPECT_EQ(SPARSE_HEADER_MAGIC, header.magic);
    EXPECT_EQ(1, header.major_version);
    EXPECT_EQ(0, header.minor_version);
    EXPECT_EQ(28, header.file_hdr_sz);
    EXPECT_EQ(12, header.chunk_hdr_sz);
    EXPECT_EQ((uint32_t)kBlockSize, header.blk_sz);
    EXPECT_EQ(testsize, GetFileSize("a1"));
    EXPECT_EQ((GetFileSize("a1") + header.blk_sz - 1) / header.blk_sz, header.total_blks);
    EXPECT_EQ(1U, header.total_chunks);
}
// Test with missing input files for error.
TEST_F(SparseTest, Img2SImgErrors) {
    EXPECT_EQ(0, !(RunImg2SImg("a90", "a90sparse")));
}
TEST_F(SparseTest, SImg2ImgErrors) {
    EXPECT_EQ(0, !(RunSImg2Img("a91sparse", "a91unsparse")));
}

TEST_F(SparseTest, Append2SImgBasic) {
    CreateTestFile("b1", 2 * 1024 * 1024, true);
    // AddPadding also creates a file if none exists
    AddPadding("b1-pada", kBlockSize, 0xA5);
    AddPadding("b1-padb", kBlockSize * 2, 0x5A);
    EXPECT_EQ(0, RunImg2SImg("b1", "b1-sparse"));
    EXPECT_EQ(0, RunAppend2SImg("b1-sparse", "b1-pada"));
    EXPECT_EQ(0, RunAppend2SImg("b1-sparse", "b1-padb"));
    EXPECT_EQ(0, RunSImg2Img("b1-sparse", "b1-unsparse"));
    CreateTestFile("b1-reference", 2 * 1024 * 1024, true);
    AddPadding("b1-reference", kBlockSize, 0xA5);
    AddPadding("b1-reference", kBlockSize * 2, 0x5A);
    EXPECT_EQ(0, UnsparseCmpFile("b1-reference", "b1-unsparse"));
}
TEST_F(SparseTest, Append2SImgUnalignedInput) {
    // Check that appends need to be multiple of block size (really?)
    CreateTestFile("b2", 1024 * 1024, true);
    AddPadding("b2-pada", kBlockSize / 2, 0xA5);
    AddPadding("b2-padb", kBlockSize / 4, 0x5A);
    EXPECT_EQ(0, RunImg2SImg("b2", "b2-sparse"));
    EXPECT_EQ(0, !(RunAppend2SImg("b2-sparse", "b2-pada")));
    EXPECT_EQ(0, !(RunAppend2SImg("b2-sparse", "b2-padb")));
}
TEST_F(SparseTest, Append2SImgErrors) {
    // Check that missing input exits with an error.
    CreateTestFile("b3", kBlockSize, false);
    EXPECT_EQ(0, !(RunAppend2SImg("b99-sparse", "b3")));
    EXPECT_EQ(0, !(RunAppend2SImg("b3", "b99")));
}

// TODO: test libsparse (the library) directly.

}  // namespace android

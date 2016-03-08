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

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <gtest/gtest.h>

#include <trusty/lib/storage.h>

#define TRUSTY_DEVICE_NAME "/dev/trusty-ipc-dev0"

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

static inline bool is_32bit_aligned(size_t sz)
{
    return ((sz & 0x3) == 0);
}

static inline bool is_valid_size(size_t sz) {
    return (sz > 0) && is_32bit_aligned(sz);
}

static bool is_valid_offset(storage_off_t off)
{
    return (off & 0x3) == 0ULL;
}

static void fill_pattern32(uint32_t *buf, size_t len, storage_off_t off)
{
    size_t cnt = len / sizeof(uint32_t);
    uint32_t pattern = (uint32_t)(off / sizeof(uint32_t));
    while (cnt--) {
        *buf++ = pattern++;
    }
}

static bool check_pattern32(const uint32_t *buf, size_t len, storage_off_t off)
{
    size_t cnt = len / sizeof(uint32_t);
    uint32_t pattern = (uint32_t)(off / sizeof(uint32_t));
    while (cnt--) {
        if (*buf != pattern)
            return false;
        buf++;
        pattern++;
    }
    return true;
}

static bool check_value32(const uint32_t *buf, size_t len, uint32_t val)
{
    size_t cnt = len / sizeof(uint32_t);
    while (cnt--) {
        if (*buf != val)
            return false;
        buf++;
    }
    return true;
}

using testing::TestWithParam;

class StorageServiceTest : public virtual TestWithParam<const char *> {
public:
    StorageServiceTest() {}
    virtual ~StorageServiceTest() {}

    virtual void SetUp() {
        port_ = GetParam();
        test_buf_ = NULL;
        int rc = storage_open_session(TRUSTY_DEVICE_NAME, &session_, port_);
        ASSERT_EQ(0, rc);
    }

    virtual void TearDown() {
        if (test_buf_) {
            delete[] test_buf_;
            test_buf_ = NULL;
        }
        storage_close_session(session_);
    }

    void WriteReadAtOffsetHelper(file_handle_t handle, size_t blk, size_t cnt, bool complete);

    void WriteZeroChunk(file_handle_t handle, storage_off_t off, size_t chunk_len, bool complete);
    void WritePatternChunk(file_handle_t handle, storage_off_t off, size_t chunk_len, bool complete);
    void WritePattern(file_handle_t handle, storage_off_t off, size_t data_len, size_t chunk_len, bool complete);

    void ReadChunk(file_handle_t handle, storage_off_t off, size_t chunk_len,
                   size_t head_len, size_t pattern_len, size_t tail_len);
    void ReadPattern(file_handle_t handle, storage_off_t off, size_t data_len, size_t chunk_len);
    void ReadPatternEOF(file_handle_t handle, storage_off_t off, size_t chunk_len, size_t exp_len);

protected:
    const char *port_;
    uint32_t *test_buf_;
    storage_session_t session_;
};

INSTANTIATE_TEST_CASE_P(SS_TD_Tests, StorageServiceTest,   ::testing::Values(STORAGE_CLIENT_TD_PORT));
INSTANTIATE_TEST_CASE_P(SS_TDEA_Tests, StorageServiceTest, ::testing::Values(STORAGE_CLIENT_TDEA_PORT));
INSTANTIATE_TEST_CASE_P(SS_TP_Tests, StorageServiceTest,   ::testing::Values(STORAGE_CLIENT_TP_PORT));


void StorageServiceTest::WriteZeroChunk(file_handle_t handle, storage_off_t off,
                                       size_t chunk_len, bool complete)
{
    int rc;
    uint32_t data_buf[chunk_len/sizeof(uint32_t)];

    ASSERT_PRED1(is_valid_size, chunk_len);
    ASSERT_PRED1(is_valid_offset, off);

    memset(data_buf, 0, chunk_len);

    if (complete)
        rc = storage_write(session_, handle, off, data_buf, sizeof(data_buf));
    else
        rc = storage_write_ext(session_, handle, off, data_buf, sizeof(data_buf), 0);

    ASSERT_EQ((int)chunk_len, rc);
}

void StorageServiceTest::WritePatternChunk(file_handle_t handle, storage_off_t off,
                                           size_t chunk_len, bool complete)
{
    int rc;
    uint32_t data_buf[chunk_len/sizeof(uint32_t)];

    ASSERT_PRED1(is_valid_size, chunk_len);
    ASSERT_PRED1(is_valid_offset, off);

    fill_pattern32(data_buf, chunk_len, off);

    if (complete)
        rc = storage_write(session_, handle, off, data_buf, sizeof(data_buf));
    else
        rc = storage_write_ext(session_, handle, off, data_buf, sizeof(data_buf), 0);

    ASSERT_EQ((int)chunk_len, rc);
}

void StorageServiceTest::WritePattern(file_handle_t handle, storage_off_t off,
                                      size_t data_len, size_t chunk_len, bool complete)
{
    ASSERT_PRED1(is_valid_size, data_len);
    ASSERT_PRED1(is_valid_size, chunk_len);

    while (data_len) {
        if (data_len < chunk_len)
            chunk_len = data_len;
        WritePatternChunk(handle, off, chunk_len, (chunk_len == data_len) && complete);
        ASSERT_FALSE(HasFatalFailure());
        off += chunk_len;
        data_len -= chunk_len;
    }
}

void StorageServiceTest::ReadChunk(file_handle_t handle,
                                   storage_off_t off, size_t chunk_len,
                                   size_t head_len, size_t pattern_len,
                                   size_t tail_len)
{
    int rc;
    uint32_t data_buf[chunk_len/sizeof(uint32_t)];
    uint8_t *data_ptr = (uint8_t *)data_buf;

    ASSERT_PRED1(is_valid_size, chunk_len);
    ASSERT_PRED1(is_valid_offset, off);
    ASSERT_EQ(head_len + pattern_len + tail_len, chunk_len);

    rc = storage_read(session_, handle, off, data_buf, chunk_len);
    ASSERT_EQ((int)chunk_len, rc);

    if (head_len) {
        ASSERT_TRUE(check_value32((const uint32_t *)data_ptr, head_len, 0));
        data_ptr += head_len;
        off += head_len;
    }

    if (pattern_len) {
        ASSERT_TRUE(check_pattern32((const uint32_t *)data_ptr, pattern_len, off));
        data_ptr += pattern_len;
    }

    if (tail_len) {
        ASSERT_TRUE(check_value32((const uint32_t *)data_ptr, tail_len, 0));
    }
}

void StorageServiceTest::ReadPattern(file_handle_t handle, storage_off_t off,
                                     size_t data_len, size_t chunk_len)
{
    int rc;
    uint32_t data_buf[chunk_len/sizeof(uint32_t)];

    ASSERT_PRED1(is_valid_size, chunk_len);
    ASSERT_PRED1(is_valid_size, data_len);
    ASSERT_PRED1(is_valid_offset, off);

    while (data_len) {
        if (chunk_len > data_len)
            chunk_len = data_len;
        rc = storage_read(session_, handle, off, data_buf, sizeof(data_buf));
        ASSERT_EQ((int)chunk_len, rc);
        ASSERT_TRUE(check_pattern32(data_buf, chunk_len, off));
        off += chunk_len;
        data_len -= chunk_len;
    }
}

void StorageServiceTest::ReadPatternEOF(file_handle_t handle, storage_off_t off,
                                        size_t chunk_len, size_t exp_len)
{
    int rc;
    size_t bytes_read = 0;
    uint32_t data_buf[chunk_len/sizeof(uint32_t)];

    ASSERT_PRED1(is_valid_size, chunk_len);
    ASSERT_PRED1(is_32bit_aligned, exp_len);

    while (true) {
         rc = storage_read(session_, handle, off, data_buf, sizeof(data_buf));
         ASSERT_GE(rc, 0);
         if (rc == 0)
             break; // end of file reached
         ASSERT_PRED1(is_valid_size, (size_t)rc);
         ASSERT_TRUE(check_pattern32(data_buf, rc, off));
         off += rc;
         bytes_read += rc;
    }
    ASSERT_EQ(bytes_read, exp_len);
}

TEST_P(StorageServiceTest, CreateDelete) {
    int rc;
    file_handle_t handle;
    const char *fname = "test_create_delete_file";

    // make sure test file does not exist (expect success or -ENOENT)
    rc = storage_delete_file(session_, fname);
    rc = (rc == -ENOENT) ? 0 : rc;
    ASSERT_EQ(0, rc);

    // one more time (expect -ENOENT only)
    rc = storage_delete_file(session_, fname);
    ASSERT_EQ(-ENOENT, rc);

    // create file (expect 0)
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_CREATE_EXCLUSIVE);
    ASSERT_EQ(0, rc);

    // try to create it again while it is still opened (expect -EEXIST)
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_CREATE_EXCLUSIVE);
    ASSERT_EQ(-EEXIST, rc);

    // close it
    storage_close_file(session_, handle);

    // try to create it again while it is closed (expect -EEXIST)
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_CREATE_EXCLUSIVE);
    ASSERT_EQ(-EEXIST, rc);

    // delete file (expect 0)
    rc = storage_delete_file(session_, fname);
    ASSERT_EQ(0, rc);

    // one more time (expect -ENOENT)
    rc = storage_delete_file(session_, fname);
    ASSERT_EQ(-ENOENT, rc);
}


TEST_P(StorageServiceTest, DeleteOpened) {
    int rc;
    file_handle_t handle;
    const char *fname = "delete_opened_test_file";

    // make sure test file does not exist (expect success or -ENOENT)
    rc = storage_delete_file(session_, fname);
    rc = (rc == -ENOENT) ? 0 : rc;
    ASSERT_EQ(0, rc);

    // one more time (expect -ENOENT)
    rc = storage_delete_file(session_, fname);
    ASSERT_EQ(-ENOENT, rc);

    // open/create file (expect 0)
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_CREATE_EXCLUSIVE);
    ASSERT_EQ(0, rc);

    // delete opened file (expect 0)
    rc = storage_delete_file(session_, fname);
    ASSERT_EQ(0, rc);

    // one more time (expect -ENOENT)
    rc = storage_delete_file(session_, fname);
    ASSERT_EQ(-ENOENT, rc);

    // close file
    storage_close_file(session_, handle);

    // one more time (expect -ENOENT)
    rc = storage_delete_file(session_, fname);
    ASSERT_EQ(-ENOENT, rc);
}


TEST_P(StorageServiceTest, OpenNoCreate) {
    int rc;
    file_handle_t handle;
    const char *fname = "test_open_no_create_file";

    // make sure test file does not exist (expect success or -ENOENT)
    rc = storage_delete_file(session_, fname);
    rc = (rc == -ENOENT) ? 0 : rc;
    ASSERT_EQ(0, rc);

    // open non-existing file (expect -ENOENT)
    rc = storage_open_file(session_, &handle, fname, 0);
    ASSERT_EQ(-ENOENT, rc);

    // create file (expect 0)
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_CREATE_EXCLUSIVE);
    ASSERT_EQ(0, rc);
    storage_close_file(session_, handle);

    // open existing file (expect 0)
    rc = storage_open_file(session_, &handle, fname, 0);
    ASSERT_EQ(0, rc);

    // close it
    storage_close_file(session_, handle);

    // delete file (expect 0)
    rc = storage_delete_file(session_, fname);
    ASSERT_EQ(0, rc);
}


TEST_P(StorageServiceTest, OpenOrCreate) {
    int rc;
    file_handle_t handle;
    const char *fname = "test_open_create_file";

    // make sure test file does not exist (expect success or -ENOENT)
    rc = storage_delete_file(session_, fname);
    rc = (rc == -ENOENT) ? 0 : rc;
    ASSERT_EQ(0, rc);

    // open/create a non-existing file (expect 0)
    rc = storage_open_file(session_, &handle, fname, STORAGE_FILE_OPEN_CREATE);
    ASSERT_EQ(0, rc);
    storage_close_file(session_, handle);

    // open/create an existing file (expect 0)
    rc = storage_open_file(session_, &handle, fname, STORAGE_FILE_OPEN_CREATE);
    ASSERT_EQ(0, rc);
    storage_close_file(session_, handle);

    // delete file (expect 0)
    rc = storage_delete_file(session_, fname);
    ASSERT_EQ(0, rc);
}

TEST_P(StorageServiceTest, WriteReadSequential) {
    int rc;
    size_t blk = 2048;
    file_handle_t handle;
    const char *fname = "test_write_read_sequential";

    // make sure test file does not exist (expect success or -ENOENT)
    rc = storage_delete_file(session_, fname);
    rc = (rc == -ENOENT) ? 0 : rc;
    ASSERT_EQ(0, rc);

    // create file.
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_CREATE_EXCLUSIVE);
    ASSERT_EQ(0, rc);

    // write a bunch of blocks (sequentially)
    WritePattern(handle, 0, 32 * blk, blk, true);
    ASSERT_FALSE(HasFatalFailure());

    ReadPattern(handle, 0, 32 * blk, blk);
    ASSERT_FALSE(HasFatalFailure());

    // close file
    storage_close_file(session_, handle);

    // open the same file again
    rc = storage_open_file(session_, &handle, fname, 0);
    ASSERT_EQ(0, rc);

    // read data back (sequentially) and check pattern again
    ReadPattern(handle, 0, 32 * blk, blk);
    ASSERT_FALSE(HasFatalFailure());

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}


TEST_P(StorageServiceTest, OpenTruncate) {
    int rc;
    uint32_t val;
    size_t blk = 2048;
    file_handle_t handle;
    const char *fname = "test_open_truncate";

    // make sure test file does not exist (expect success or -ENOENT)
    rc = storage_delete_file(session_, fname);
    rc = (rc == -ENOENT) ? 0 : rc;
    ASSERT_EQ(0, rc);

    // create file.
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_CREATE_EXCLUSIVE);
    ASSERT_EQ(0, rc);

    // write some data and read it back
    WritePatternChunk(handle, 0, blk, true);
    ASSERT_FALSE(HasFatalFailure());

    ReadPattern(handle, 0, blk, blk);
    ASSERT_FALSE(HasFatalFailure());

     // close file
    storage_close_file(session_, handle);

    // reopen with truncate
    rc = storage_open_file(session_, &handle, fname, STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    /* try to read data back (expect no data) */
    rc = storage_read(session_, handle, 0LL, &val, sizeof(val));
    ASSERT_EQ(0, rc);

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}


TEST_P(StorageServiceTest, OpenSame) {
    int rc;
    file_handle_t handle1;
    file_handle_t handle2;
    file_handle_t handle3;
    const char *fname = "test_open_same_file";

    // open/create file (expect 0)
    rc = storage_open_file(session_, &handle1, fname, STORAGE_FILE_OPEN_CREATE);
    ASSERT_EQ(0, rc);
    storage_close_file(session_, handle1);

    // open an existing file first time (expect 0)
    rc = storage_open_file(session_, &handle1, fname, 0);
    ASSERT_EQ(0, rc);

    // open the same file second time (expect 0)
    rc = storage_open_file(session_, &handle2, fname, 0);
    ASSERT_EQ(0, rc);
    ASSERT_NE(handle1, handle2);

    // delete file (expect 0)
    rc = storage_delete_file(session_, fname);
    ASSERT_EQ(0, rc);

    // open deleted file (expect -ENOENT)
    rc = storage_open_file(session_, &handle3, fname, 0);
    ASSERT_EQ(-ENOENT, rc);

    // close them all
    storage_close_file(session_, handle1);
    storage_close_file(session_, handle2);
}


TEST_P(StorageServiceTest, OpenMany) {
    int rc;
    file_handle_t handles[10];
    char filename[10];
    const char *fname_fmt = "mf%d";

    // open or create a bunch of files (expect 0)
    for (uint i = 0; i < ARRAY_SIZE(handles); ++i) {
        snprintf(filename, sizeof(filename), fname_fmt, i);
        rc = storage_open_file(session_, &handles[i], filename, STORAGE_FILE_OPEN_CREATE);
        ASSERT_EQ(0, rc);
    }

    // check that all handles are different
    for (uint i = 0; i < ARRAY_SIZE(handles)-1; i++) {
        for (uint j = i+1; j < ARRAY_SIZE(handles); j++) {
            ASSERT_NE(handles[i], handles[j]);
        }
    }

    // close them all
    for (uint i = 0; i < ARRAY_SIZE(handles); ++i) {
        storage_close_file(session_, handles[i]);
    }

    // open all files without CREATE flags (expect 0)
    for (uint i = 0; i < ARRAY_SIZE(handles); ++i) {
        snprintf(filename, sizeof(filename), fname_fmt, i);
        rc = storage_open_file(session_, &handles[i], filename, 0);
        ASSERT_EQ(0, rc);
    }

    // check that all handles are different
    for (uint i = 0; i < ARRAY_SIZE(handles)-1; i++) {
        for (uint j = i+1; j < ARRAY_SIZE(handles); j++) {
            ASSERT_NE(handles[i], handles[j]);
        }
    }

    // close and remove all test files
    for (uint i = 0; i < ARRAY_SIZE(handles); ++i) {
        storage_close_file(session_, handles[i]);
        snprintf(filename, sizeof(filename), fname_fmt, i);
        rc = storage_delete_file(session_, filename);
        ASSERT_EQ(0, rc);
    }
}


TEST_P(StorageServiceTest, ReadAtEOF) {
    int rc;
    uint32_t val;
    size_t blk = 2048;
    file_handle_t handle;
    const char *fname = "test_read_eof";

    // open/create/truncate file
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // write block at offset 0
    WritePatternChunk(handle, 0, blk, true);
    ASSERT_FALSE(HasFatalFailure());

    // close file
    storage_close_file(session_, handle);

    // open same file again
    rc = storage_open_file(session_, &handle, fname, 0);
    ASSERT_EQ(0, rc);

    // read the whole block back and check pattern again
    ReadPattern(handle, 0, blk, blk);
    ASSERT_FALSE(HasFatalFailure());

    // read at end of file (expected 0 bytes)
    rc = storage_read(session_, handle, blk, &val, sizeof(val));
    ASSERT_EQ(0, rc);

    // partial read at end of the file (expected partial data)
    ReadPatternEOF(handle, blk/2, blk, blk/2);
    ASSERT_FALSE(HasFatalFailure());

    // read past end of file
    rc = storage_read(session_, handle, blk + 2, &val, sizeof(val));
    ASSERT_EQ(-EINVAL, rc);

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}


TEST_P(StorageServiceTest, GetFileSize) {
    int rc;
    size_t blk = 2048;
    storage_off_t size;
    file_handle_t handle;
    const char *fname = "test_get_file_size";

    // open/create/truncate file.
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // check file size (expect success and size == 0)
    size = 1;
    rc = storage_get_file_size(session_, handle, &size);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)0, size);

    // write block
    WritePatternChunk(handle, 0, blk, true);
    ASSERT_FALSE(HasFatalFailure());

    // check size
    rc = storage_get_file_size(session_, handle, &size);
    ASSERT_EQ(0, rc);
    ASSERT_EQ(blk, size);

    // write another block
    WritePatternChunk(handle, blk, blk, true);
    ASSERT_FALSE(HasFatalFailure());

    // check size again
    rc = storage_get_file_size(session_, handle, &size);
    ASSERT_EQ(0, rc);
    ASSERT_EQ(blk*2, size);

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}


TEST_P(StorageServiceTest, SetFileSize) {
    int rc;
    size_t blk = 2048;
    storage_off_t size;
    file_handle_t handle;
    const char *fname = "test_set_file_size";

    // open/create/truncate file.
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // check file size (expect success and size == 0)
    size = 1;
    rc = storage_get_file_size(session_, handle, &size);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)0, size);

    // write block
    WritePatternChunk(handle, 0, blk, true);
    ASSERT_FALSE(HasFatalFailure());

    // check size
    rc = storage_get_file_size(session_, handle, &size);
    ASSERT_EQ(0, rc);
    ASSERT_EQ(blk, size);

    storage_close_file(session_, handle);

    // reopen normally
    rc = storage_open_file(session_, &handle, fname, 0);
    ASSERT_EQ(0, rc);

    // check size again
    rc = storage_get_file_size(session_, handle, &size);
    ASSERT_EQ(0, rc);
    ASSERT_EQ(blk, size);

    // set file size to half
    rc = storage_set_file_size(session_, handle, blk/2);
    ASSERT_EQ(0, rc);

    // check size again (should be half of original size)
    rc = storage_get_file_size(session_, handle, &size);
    ASSERT_EQ(0, rc);
    ASSERT_EQ(blk/2, size);

    // read data back
    ReadPatternEOF(handle, 0, blk, blk/2);
    ASSERT_FALSE(HasFatalFailure());

    // set file size to 0
    rc = storage_set_file_size(session_, handle, 0);
    ASSERT_EQ(0, rc);

    // check size again (should be 0)
    rc = storage_get_file_size(session_, handle, &size);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)0LL, size);

    // try to read again
    ReadPatternEOF(handle, 0, blk, 0);
    ASSERT_FALSE(HasFatalFailure());

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}


void StorageServiceTest::WriteReadAtOffsetHelper(file_handle_t handle, size_t blk, size_t cnt, bool complete)
{
    storage_off_t off1 = blk;
    storage_off_t off2 = blk * (cnt-1);

    // write known pattern data at non-zero offset1
    WritePatternChunk(handle, off1, blk, complete);
    ASSERT_FALSE(HasFatalFailure());

    // write known pattern data at non-zero offset2
    WritePatternChunk(handle, off2, blk, complete);
    ASSERT_FALSE(HasFatalFailure());

    // read data back at offset1
    ReadPattern(handle, off1, blk, blk);
    ASSERT_FALSE(HasFatalFailure());

    // read data back at offset2
    ReadPattern(handle, off2, blk, blk);
    ASSERT_FALSE(HasFatalFailure());

    // read partially written data at end of file(expect to get data only, no padding)
    ReadPatternEOF(handle, off2 + blk/2, blk, blk/2);
    ASSERT_FALSE(HasFatalFailure());

    // read data at offset 0 (expect success and zero data)
    ReadChunk(handle, 0, blk, blk, 0, 0);
    ASSERT_FALSE(HasFatalFailure());

    // read data from gap (expect success and zero data)
    ReadChunk(handle, off1 + blk, blk, blk, 0, 0);
    ASSERT_FALSE(HasFatalFailure());

    // read partially written data (start pointing within written data)
    // (expect to get written data back and zeroes at the end)
    ReadChunk(handle, off1 + blk/2, blk, 0, blk/2, blk/2);
    ASSERT_FALSE(HasFatalFailure());

    // read partially written data (start pointing withing unwritten data)
    // expect to get zeroes at the beginning and proper data at the end
    ReadChunk(handle, off1 - blk/2, blk, blk/2, blk/2, 0);
    ASSERT_FALSE(HasFatalFailure());
}


TEST_P(StorageServiceTest, WriteReadAtOffset) {
    int rc;
    file_handle_t handle;
    size_t blk = 2048;
    size_t blk_cnt = 32;
    const char *fname = "test_write_at_offset";

    // create/truncate file.
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // write a bunch of blocks filled with zeroes
    for (uint i = 0; i < blk_cnt; i++) {
        WriteZeroChunk(handle, i * blk, blk, true);
        ASSERT_FALSE(HasFatalFailure());
    }

    WriteReadAtOffsetHelper(handle, blk, blk_cnt, true);
    ASSERT_FALSE(HasFatalFailure());

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}


TEST_P(StorageServiceTest, WriteSparse) {
    int rc;
    file_handle_t handle;
    const char *fname = "test_write_sparse";

    // open/create/truncate file.
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // write value past en of file
    uint32_t val = 0xDEADBEEF;
    rc = storage_write(session_, handle, 1, &val, sizeof(val));
    ASSERT_EQ(-EINVAL, rc);

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}

TEST_P(StorageServiceTest, CreatePersistent32K) {
    int rc;
    file_handle_t handle;
    size_t blk = 2048;
    size_t file_size = 32768;
    const char *fname = "test_persistent_32K_file";

    // create/truncate file.
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // write a bunch of blocks filled with pattern
    WritePattern(handle, 0, file_size, blk, true);
    ASSERT_FALSE(HasFatalFailure());

    // close but do not delete file
    storage_close_file(session_, handle);
}

TEST_P(StorageServiceTest, ReadPersistent32k) {
    int rc;
    file_handle_t handle;
    size_t exp_len = 32 * 1024;
    const char *fname = "test_persistent_32K_file";

    // create/truncate file.
    rc = storage_open_file(session_, &handle, fname, 0);
    ASSERT_EQ(0, rc);

    ReadPatternEOF(handle, 0, 2048, exp_len);
    ASSERT_FALSE(HasFatalFailure());

    ReadPatternEOF(handle, 0, 1024, exp_len);
    ASSERT_FALSE(HasFatalFailure());

    ReadPatternEOF(handle, 0,  332, exp_len);
    ASSERT_FALSE(HasFatalFailure());

    // close but do not delete file
    storage_close_file(session_, handle);
}

TEST_P(StorageServiceTest, CleanUpPersistent32K) {
    int rc;
    const char *fname = "test_persistent_32K_file";
    rc = storage_delete_file(session_, fname);
    rc = (rc == -ENOENT) ? 0 : rc;
    ASSERT_EQ(0, rc);
}

TEST_P(StorageServiceTest, CreatePersistent1M) {
    int rc;
    file_handle_t handle;
    size_t file_size = 1024 * 1024;
    const char *fname = "test_persistent_1M_file";

    // create/truncate file.
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // write a bunch of blocks filled with pattern
    WritePattern(handle, 0, file_size, 2048, true);
    ASSERT_FALSE(HasFatalFailure());

    // close but do not delete file
    storage_close_file(session_, handle);
}

TEST_P(StorageServiceTest, ReadPersistent1M) {
    int rc;
    file_handle_t handle;
    size_t exp_len = 1024 * 1024;
    const char *fname = "test_persistent_1M_file";

    // create/truncate file.
    rc = storage_open_file(session_, &handle, fname, 0);
    ASSERT_EQ(0, rc);

    ReadPatternEOF(handle, 0, 2048, exp_len);
    ASSERT_FALSE(HasFatalFailure());

    ReadPatternEOF(handle, 0, 1024, exp_len);
    ASSERT_FALSE(HasFatalFailure());

    ReadPatternEOF(handle, 0,  332, exp_len);
    ASSERT_FALSE(HasFatalFailure());

    // close but do not delete file
    storage_close_file(session_, handle);
}

TEST_P(StorageServiceTest, CleanUpPersistent1M) {
    int rc;
    const char *fname = "test_persistent_1M_file";
    rc = storage_delete_file(session_, fname);
    rc = (rc == -ENOENT) ? 0 : rc;
    ASSERT_EQ(0, rc);
}

TEST_P(StorageServiceTest, WriteReadLong) {
    int rc;
    file_handle_t handle;
    size_t wc = 10000;
    const char *fname = "test_write_read_long";

    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    test_buf_ = new uint32_t[wc];
    fill_pattern32(test_buf_, wc * sizeof(uint32_t), 0);
    rc = storage_write(session_, handle, 0, test_buf_, wc * sizeof(uint32_t));
    ASSERT_EQ((int)(wc * sizeof(uint32_t)), rc);

    rc = storage_read(session_, handle, 0, test_buf_, wc * sizeof(uint32_t));
    ASSERT_EQ((int)(wc * sizeof(uint32_t)), rc);
    ASSERT_TRUE(check_pattern32(test_buf_, wc * sizeof(uint32_t), 0));

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}

TEST_P(StorageServiceTest, TransactDiscardInactive) {
    int rc;

    // discard current transaction (there should not be any)
    rc = storage_end_transaction(session_, false);
    ASSERT_EQ(0, rc);

    // try it again
    rc = storage_end_transaction(session_, false);
    ASSERT_EQ(0, rc);
}

TEST_P(StorageServiceTest, TransactCommitInactive) {
    int rc;

    // try to commit current transaction
    rc = storage_end_transaction(session_, true);
    ASSERT_EQ(0, rc);

    // try it again
    rc = storage_end_transaction(session_, true);
    ASSERT_EQ(0, rc);
}

TEST_P(StorageServiceTest, TransactDiscardWrite) {

    int rc;
    file_handle_t handle;
    size_t blk = 2048;
    size_t exp_len = 32 * 1024;
    storage_off_t fsize = (storage_off_t)(-1);
    const char *fname = "test_transact_discard_write";

    // open create truncate file (with commit)
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // check file size
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)0, fsize);

    // write (without commit)
    WritePattern(handle, 0, exp_len, blk, false);
    ASSERT_FALSE(HasFatalFailure());

    // check file size
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len, fsize);

    // abort current transaction
    rc = storage_end_transaction(session_, false);
    ASSERT_EQ(0, rc);

    // check file size
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)0, fsize);

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}


TEST_P(StorageServiceTest, TransactDiscardWriteAppend) {

    int rc;
    file_handle_t handle;
    size_t blk = 2048;
    size_t exp_len = 32 * 1024;
    storage_off_t fsize = (storage_off_t)(-1);
    const char *fname = "test_transact_write_append";

    // open create truncate file (with commit)
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // write data with commit
    WritePattern(handle, 0, exp_len/2, blk, true);
    ASSERT_FALSE(HasFatalFailure());

    // write data without commit
    WritePattern(handle, exp_len/2, exp_len/2, blk, false);
    ASSERT_FALSE(HasFatalFailure());

    // check file size (should be exp_len)
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len, fsize);

    // discard transaction
    rc = storage_end_transaction(session_, false);
    ASSERT_EQ(0, rc);

    // check file size, it should be exp_len/2
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len/2, fsize);

    // check file data
    ReadPatternEOF(handle, 0, blk, exp_len/2);
    ASSERT_FALSE(HasFatalFailure());

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}

TEST_P(StorageServiceTest, TransactDiscardWriteRead) {

    int rc;
    file_handle_t handle;
    size_t blk = 2048;
    storage_off_t fsize = (storage_off_t)(-1);
    const char *fname = "test_transact_discard_write_read";

    // open create truncate file (with commit)
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // check file size
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)0, fsize);

    // Fill with zeroes (with commit)
    for (uint i = 0; i < 32; i++) {
        WriteZeroChunk(handle, i * blk, blk, true);
        ASSERT_FALSE(HasFatalFailure());
    }

    // check that test chunk is filled with zeroes
    ReadChunk(handle, blk, blk, blk, 0, 0);
    ASSERT_FALSE(HasFatalFailure());

    // write test pattern (without commit)
    WritePattern(handle, blk, blk, blk, false);
    ASSERT_FALSE(HasFatalFailure());

    // read it back an check pattern
    ReadChunk(handle, blk, blk, 0, blk, 0);
    ASSERT_FALSE(HasFatalFailure());

    // abort current transaction
    rc = storage_end_transaction(session_, false);
    ASSERT_EQ(0, rc);

    // read same chunk back (should be filled with zeros)
    ReadChunk(handle, blk, blk, blk, 0, 0);
    ASSERT_FALSE(HasFatalFailure());

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}

TEST_P(StorageServiceTest, TransactDiscardWriteMany) {
    int rc;
    file_handle_t handle1;
    file_handle_t handle2;
    size_t blk = 2048;
    size_t exp_len1 = 32 * 1024;
    size_t exp_len2 = 31 * 1024;
    storage_off_t fsize = (storage_off_t)(-1);
    const char *fname1 = "test_transact_discard_write_file1";
    const char *fname2 = "test_transact_discard_write_file2";

    // open create truncate (with commit)
    rc = storage_open_file(session_, &handle1, fname1,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // open create truncate (with commit)
    rc = storage_open_file(session_, &handle2, fname2,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // file1: fill file with pattern (without commit)
    WritePattern(handle1, 0, exp_len1, blk, false);
    ASSERT_FALSE(HasFatalFailure());

    // file2: fill file with pattern (without commit)
    WritePattern(handle2, 0, exp_len2, blk, false);
    ASSERT_FALSE(HasFatalFailure());

    // check file size, it should be exp_len1
    rc = storage_get_file_size(session_, handle1, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len1, fsize);

    // check file size, it should be exp_len2
    rc = storage_get_file_size(session_, handle2, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len2, fsize);

    // commit transaction
    rc = storage_end_transaction(session_, false);
    ASSERT_EQ(0, rc);

    // check file size, it should be exp_len1
    rc = storage_get_file_size(session_, handle1, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)0, fsize);

    // check file size, it should be exp_len2
    rc = storage_get_file_size(session_, handle2, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)0, fsize);

    // check data
    ReadPatternEOF(handle1, 0, blk, 0);
    ASSERT_FALSE(HasFatalFailure());

    ReadPatternEOF(handle2, 0, blk, 0);
    ASSERT_FALSE(HasFatalFailure());

    // cleanup
    storage_close_file(session_, handle1);
    storage_delete_file(session_, fname1);
    storage_close_file(session_, handle2);
    storage_delete_file(session_, fname2);
}

TEST_P(StorageServiceTest, TransactDiscardTruncate) {
    int rc;
    file_handle_t handle;
    size_t blk = 2048;
    size_t exp_len = 32 * 1024;
    storage_off_t fsize = (storage_off_t)(-1);
    const char *fname = "test_transact_discard_truncate";

    // open create truncate file (with commit)
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // write data (with commit)
    WritePattern(handle, 0, exp_len, blk, true);
    ASSERT_FALSE(HasFatalFailure());

    // check file size
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len, fsize);

    // close file
    storage_close_file(session_, handle);

    // open truncate file (without commit)
    rc = storage_open_file_ext(session_, &handle, fname, STORAGE_FILE_OPEN_TRUNCATE, 0);
    ASSERT_EQ(0, rc);

    // check file size
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)0, fsize);

    // abort current transaction
    rc = storage_end_transaction(session_, false);
    ASSERT_EQ(0, rc);

    // check file size (should be an oruginal size)
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len, fsize);

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}

TEST_P(StorageServiceTest, TransactDiscardSetSize) {
    int rc;
    file_handle_t handle;
    size_t blk = 2048;
    size_t exp_len = 32 * 1024;
    storage_off_t fsize = (storage_off_t)(-1);
    const char *fname = "test_transact_discard_set_size";

    // open create truncate file (with commit)
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // write data (with commit)
    WritePattern(handle, 0, exp_len, blk, true);
    ASSERT_FALSE(HasFatalFailure());

    // check file size
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len, fsize);

    // set file size to half of original (no commit)
    rc = storage_set_file_size_ext(session_, handle,  (storage_off_t)exp_len/2, 0);
    ASSERT_EQ(0, rc);

    // check file size
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len/2, fsize);

    // set file size to 1/3 of original (no commit)
    rc = storage_set_file_size_ext(session_, handle,  (storage_off_t)exp_len/3, 0);
    ASSERT_EQ(0, rc);

    // check file size
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len/3, fsize);

    // abort current transaction
    rc = storage_end_transaction(session_, false);
    ASSERT_EQ(0, rc);

    // check file size (should be an original size)
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len, fsize);

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}

TEST_P(StorageServiceTest, TransactDiscardDelete) {
    int rc;
    file_handle_t handle;
    size_t blk = 2048;
    size_t exp_len = 32 * 1024;
    storage_off_t fsize = (storage_off_t)(-1);
    const char *fname = "test_transact_discard_delete";

    // open create truncate file (with commit)
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // write data (with commit)
    WritePattern(handle, 0, exp_len, blk, true);
    ASSERT_FALSE(HasFatalFailure());

    // close it
    storage_close_file(session_, handle);

    // delete file (without commit)
    rc = storage_delete_file_ext(session_, fname, 0);
    ASSERT_EQ(0, rc);

    // try to open it (should fail)
    rc = storage_open_file(session_, &handle, fname, 0);
    ASSERT_EQ(-ENOENT, rc);

    // abort current transaction
    rc = storage_end_transaction(session_, false);
    ASSERT_EQ(0, rc);

    // try to open it
    rc = storage_open_file(session_, &handle, fname, 0);
    ASSERT_EQ(0, rc);

    // check file size (should be an original size)
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len, fsize);

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}

TEST_P(StorageServiceTest, TransactDiscardDelete2) {
    int rc;
    file_handle_t handle;
    file_handle_t handle1;
    size_t blk = 2048;
    size_t exp_len = 32 * 1024;
    storage_off_t fsize = (storage_off_t)(-1);
    const char *fname = "test_transact_discard_delete";

    // open create truncate file (with commit)
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // write data (with commit)
    WritePattern(handle, 0, exp_len, blk, true);
    ASSERT_FALSE(HasFatalFailure());

    // delete file (without commit)
    rc = storage_delete_file_ext(session_, fname, 0);
    ASSERT_EQ(0, rc);

    // try to open it (should fail)
    rc = storage_open_file(session_, &handle1, fname, 0);
    ASSERT_EQ(-ENOENT, rc);

    // abort current transaction
    rc = storage_end_transaction(session_, false);
    ASSERT_EQ(0, rc);

    // try to open it
    rc = storage_open_file(session_, &handle1, fname, 0);
    ASSERT_EQ(0, rc);

    // check file size (should be an original size)
    rc = storage_get_file_size(session_, handle1, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len, fsize);

    // cleanup
    storage_close_file(session_, handle1);
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}


TEST_P(StorageServiceTest, DISABLED_TransactDiscardCreate) {
    int rc;
    file_handle_t handle;
    const char *fname = "test_transact_discard_create_excl";

    // delete test file just in case
    storage_delete_file(session_, fname);

    // create file (without commit)
    rc = storage_open_file_ext(session_, &handle, fname,
                               STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_CREATE_EXCLUSIVE,
                               0);
    ASSERT_EQ(0, rc);

    // abort current transaction
    rc = storage_end_transaction(session_, false);
    ASSERT_EQ(0, rc);

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}

TEST_P(StorageServiceTest, TransactCommitWrites) {

    int rc;
    file_handle_t handle;
    size_t blk = 2048;
    size_t exp_len = 32 * 1024;
    storage_off_t fsize = (storage_off_t)(-1);
    const char *fname = "test_transact_commit_writes";

    // open create truncate file (with commit)
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // write (without commit)
    WritePattern(handle, 0, exp_len/2, blk, false);
    ASSERT_FALSE(HasFatalFailure());

    // wite more data (without commit)
    WritePattern(handle, exp_len/2, exp_len/2, blk, false);
    ASSERT_FALSE(HasFatalFailure());

    // commit current transaction
    rc = storage_end_transaction(session_, true);
    ASSERT_EQ(0, rc);

    // check file size, it should be exp_len
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len, fsize);

    // check data
    ReadPatternEOF(handle, 0, blk, exp_len);
    ASSERT_FALSE(HasFatalFailure());

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}


TEST_P(StorageServiceTest, TransactCommitWrites2) {

    int rc;
    file_handle_t handle;
    size_t blk = 2048;
    storage_off_t fsize = (storage_off_t)(-1);
    const char *fname = "test_transact_commit_writes2";

    // open create truncate file (with commit)
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // check file size
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)0, fsize);

    // Fill with zeroes (with commit)
    for (uint i = 0; i < 8; i++) {
        WriteZeroChunk(handle, i * blk, blk, true);
        ASSERT_FALSE(HasFatalFailure());
    }

    // check that test chunks is filled with zeroes
    ReadChunk(handle, blk, blk, blk, 0, 0);
    ASSERT_FALSE(HasFatalFailure());

    ReadChunk(handle, 2 * blk, blk, blk, 0, 0);
    ASSERT_FALSE(HasFatalFailure());

    // write test pattern (without commit)
    WritePattern(handle, blk, blk, blk, false);
    ASSERT_FALSE(HasFatalFailure());

    // write test pattern (without commit)
    WritePattern(handle, 2 * blk, blk, blk, false);
    ASSERT_FALSE(HasFatalFailure());

    // read it back an check pattern
    ReadChunk(handle, blk, blk, 0, blk, 0);
    ASSERT_FALSE(HasFatalFailure());

    ReadChunk(handle, 2 * blk, blk, 0, blk, 0);
    ASSERT_FALSE(HasFatalFailure());

    // commit current transaction
    rc = storage_end_transaction(session_, true);
    ASSERT_EQ(0, rc);

    // read same chunk back (should be filled with data)
    ReadChunk(handle, blk, blk, 0, blk, 0);
    ASSERT_FALSE(HasFatalFailure());

    ReadChunk(handle, 2 * blk, blk, 0, blk, 0);
    ASSERT_FALSE(HasFatalFailure());

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}

TEST_P(StorageServiceTest, TransactCommitSetSize) {
    int rc;
    file_handle_t handle;
    size_t blk = 2048;
    size_t exp_len = 32 * 1024;
    storage_off_t fsize = (storage_off_t)(-1);
    const char *fname = "test_transact_commit_set_size";

    // open create truncate file (with commit)
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // write data (with commit)
    WritePattern(handle, 0, exp_len, blk, true);
    ASSERT_FALSE(HasFatalFailure());

    // check file size
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len, fsize);

    // set file size to half of original (no commit)
    rc = storage_set_file_size_ext(session_, handle,  (storage_off_t)exp_len/2, 0);
    ASSERT_EQ(0, rc);

    // check file size
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len/2, fsize);

    // set file size to 1/3 of original (no commit)
    rc = storage_set_file_size_ext(session_, handle,  (storage_off_t)exp_len/3, 0);
    ASSERT_EQ(0, rc);

    // check file size
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len/3, fsize);

    // commit current transaction
    rc = storage_end_transaction(session_, true);
    ASSERT_EQ(0, rc);

    // check file size (should be 1/3 of an original size)
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len/3, fsize);

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}


TEST_P(StorageServiceTest, TransactCommitDelete) {
    int rc;
    file_handle_t handle;
    size_t blk = 2048;
    size_t exp_len = 32 * 1024;
    const char *fname = "test_transact_commit_delete";

    // open create truncate file (with commit)
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // write data (with commit)
    WritePattern(handle, 0, exp_len, blk, true);
    ASSERT_FALSE(HasFatalFailure());

    // close it
    storage_close_file(session_, handle);

    // delete file (without commit)
    rc = storage_delete_file_ext(session_, fname, 0);
    ASSERT_EQ(0, rc);

    // try to open it (should fail)
    rc = storage_open_file(session_, &handle, fname, 0);
    ASSERT_EQ(-ENOENT, rc);

    // commit current transaction
    rc = storage_end_transaction(session_, true);
    ASSERT_EQ(0, rc);

    // try to open it
    rc = storage_open_file(session_, &handle, fname, 0);
    ASSERT_EQ(-ENOENT, rc);
}


TEST_P(StorageServiceTest, TransactCommitTruncate) {
    int rc;
    file_handle_t handle;
    size_t blk = 2048;
    size_t exp_len = 32 * 1024;
    storage_off_t fsize = (storage_off_t)(-1);
    const char *fname = "test_transact_commit_truncate";

    // open create truncate file (with commit)
    rc = storage_open_file(session_, &handle, fname,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // write data (with commit)
    WritePattern(handle, 0, exp_len, blk, true);
    ASSERT_FALSE(HasFatalFailure());

    // check file size
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len, fsize);

    // close file
    storage_close_file(session_, handle);

    // open truncate file (without commit)
    rc = storage_open_file_ext(session_, &handle, fname, STORAGE_FILE_OPEN_TRUNCATE, 0);
    ASSERT_EQ(0, rc);

    // check file size
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)0, fsize);

    // commit current transaction
    rc = storage_end_transaction(session_, true);
    ASSERT_EQ(0, rc);

    // check file size (should be an original size)
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)0, fsize);

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}

TEST_P(StorageServiceTest, TransactCommitCreate) {
    int rc;
    file_handle_t handle;
    storage_off_t fsize = (storage_off_t)(-1);
    const char *fname = "test_transact_commit_create";

    // delete test file just in case
    storage_delete_file(session_, fname);

    // create file (without commit)
    rc = storage_open_file_ext(session_, &handle, fname,
                               STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_CREATE_EXCLUSIVE,
                               0);
    ASSERT_EQ(0, rc);

    // check file size
    rc = storage_get_file_size(session_, handle, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)0, fsize);

    // close file
    storage_close_file(session_, handle);

    // commit current transaction
    rc = storage_end_transaction(session_, true);
    ASSERT_EQ(0, rc);

    // normal open
    rc = storage_open_file(session_, &handle, fname, 0);
    ASSERT_EQ(0, rc);

    // cleanup
    storage_close_file(session_, handle);
    storage_delete_file(session_, fname);
}

TEST_P(StorageServiceTest, TransactCommitCreatMany) {
    int rc;
    file_handle_t handle1;
    file_handle_t handle2;
    storage_off_t fsize = (storage_off_t)(-1);
    const char *fname1 = "test_transact_commit_create1";
    const char *fname2 = "test_transact_commit_create2";

    // delete test file just in case
    storage_delete_file(session_, fname1);
    storage_delete_file(session_, fname2);

    // create file (without commit)
    rc = storage_open_file_ext(session_, &handle1, fname1,
                               STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_CREATE_EXCLUSIVE,
                               0);
    ASSERT_EQ(0, rc);

    // create file (without commit)
    rc = storage_open_file_ext(session_, &handle2, fname2,
                               STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_CREATE_EXCLUSIVE,
                               0);
    ASSERT_EQ(0, rc);

    // check file sizes
    rc = storage_get_file_size(session_, handle1, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)0, fsize);

    rc = storage_get_file_size(session_, handle1, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)0, fsize);

    // close files
    storage_close_file(session_, handle1);
    storage_close_file(session_, handle2);

    // commit current transaction
    rc = storage_end_transaction(session_, true);
    ASSERT_EQ(0, rc);

    // normal open
    rc = storage_open_file(session_, &handle1, fname1, 0);
    ASSERT_EQ(0, rc);

    rc = storage_open_file(session_, &handle2, fname2, 0);
    ASSERT_EQ(0, rc);

    // cleanup
    storage_close_file(session_, handle1);
    storage_delete_file(session_, fname1);
    storage_close_file(session_, handle2);
    storage_delete_file(session_, fname2);
}


TEST_P(StorageServiceTest, TransactCommitWriteMany) {
    int rc;
    file_handle_t handle1;
    file_handle_t handle2;
    size_t blk = 2048;
    size_t exp_len1 = 32 * 1024;
    size_t exp_len2 = 31 * 1024;
    storage_off_t fsize = (storage_off_t)(-1);
    const char *fname1 = "test_transact_commit_write_file1";
    const char *fname2 = "test_transact_commit_write_file2";

    // open create truncate (with commit)
    rc = storage_open_file(session_, &handle1, fname1,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // open create truncate (with commit)
    rc = storage_open_file(session_, &handle2, fname2,
                           STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE);
    ASSERT_EQ(0, rc);

    // file1: fill file with pattern (without commit)
    WritePattern(handle1, 0, exp_len1, blk, false);
    ASSERT_FALSE(HasFatalFailure());

    // file2: fill file with pattern (without commit)
    WritePattern(handle2, 0, exp_len2, blk, false);
    ASSERT_FALSE(HasFatalFailure());

    // check file size, it should be exp_len1
    rc = storage_get_file_size(session_, handle1, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len1, fsize);

    // check file size, it should be exp_len2
    rc = storage_get_file_size(session_, handle2, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len2, fsize);

    // commit transaction
    rc = storage_end_transaction(session_, true);
    ASSERT_EQ(0, rc);

    // check file size, it should be exp_len1
    rc = storage_get_file_size(session_, handle1, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len1, fsize);

    // check file size, it should be exp_len2
    rc = storage_get_file_size(session_, handle2, &fsize);
    ASSERT_EQ(0, rc);
    ASSERT_EQ((storage_off_t)exp_len2, fsize);

    // check data
    ReadPatternEOF(handle1, 0, blk, exp_len1);
    ASSERT_FALSE(HasFatalFailure());

    ReadPatternEOF(handle2, 0, blk, exp_len2);
    ASSERT_FALSE(HasFatalFailure());

    // cleanup
    storage_close_file(session_, handle1);
    storage_delete_file(session_, fname1);
    storage_close_file(session_, handle2);
    storage_delete_file(session_, fname2);
}

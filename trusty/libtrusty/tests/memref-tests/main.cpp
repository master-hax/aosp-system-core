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

#include <assert.h>
#include <gtest/gtest.h>
#include <stdint.h>
#include <stdlib.h>

#include <trusty/tipc.h>

class MRefAPITest : public virtual testing::Test {
  public:
    MRefAPITest() { aligned_buf_ = NULL; }
    virtual ~MRefAPITest() {}

    virtual void SetUp() {
        pg_size_ = 0;
        buf_size_ = 0;
        aligned_buf_ = 0;
    }

    virtual void TearDown() {
        if (aligned_buf_) {
            free(aligned_buf_);
            aligned_buf_ = NULL;
        }
    }

    int CheckBuffer(uint8_t* p, size_t len, int v) {
        for (size_t i = 0; i < len; i++) {
            if (p[i] != (uint8_t)v) {
                return -1;
            }
        }
        return 0;
    }

  protected:
    size_t pg_size_;
    size_t buf_size_;
    uint8_t* aligned_buf_;
};

TEST_F(MRefAPITest, FinishStandalone) {
    struct tipc_memref mref;

    memset(&mref, 0, sizeof(mref));

    /* it should ne ok to call  tipc_memref_finish on zeroed buffer */
    tipc_memref_finish(&mref, 0);

    /* it should be ok to to do it again */
    tipc_memref_finish(&mref, 0);
}

TEST_F(MRefAPITest, PrepareAligned) {
    int rc;
    struct tipc_memref mref;

    pg_size_ = getpagesize();
    buf_size_ = 12 * pg_size_;
    rc = posix_memalign((void**)&aligned_buf_, pg_size_, buf_size_);
    ASSERT_EQ(rc, 0);

    /* Normal data in/data out */
    rc = tipc_memref_prepare_aligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                     aligned_buf_, buf_size_);
    EXPECT_EQ(rc, 0);

    tipc_memref_finish(&mref, 0);

    /* normal data in */
    rc = tipc_memref_prepare_aligned(&mref, TIPC_MEMREF_DATA_IN, aligned_buf_, buf_size_);
    EXPECT_EQ(rc, 0);

    tipc_memref_finish(&mref, 0);

    /* normal data in */
    rc = tipc_memref_prepare_aligned(&mref, TIPC_MEMREF_DATA_OUT, aligned_buf_, buf_size_);
    EXPECT_EQ(rc, 0);

    tipc_memref_finish(&mref, 0);
}

TEST_F(MRefAPITest, PrepareAlignedNegative) {
    int rc;
    struct tipc_memref mref;

    pg_size_ = getpagesize();
    buf_size_ = 12 * pg_size_;
    rc = posix_memalign((void**)&aligned_buf_, pg_size_, buf_size_);
    ASSERT_EQ(rc, 0);

    /* Invalid mref pointer */
    rc = tipc_memref_prepare_aligned(NULL, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT, aligned_buf_,
                                     buf_size_);
    ASSERT_EQ(rc, -EINVAL);

    /* no dorection specified  */
    rc = tipc_memref_prepare_aligned(&mref, 0, aligned_buf_, buf_size_);
    EXPECT_EQ(rc, -EINVAL);

    tipc_memref_finish(&mref, 0);

    /* bad base address */
    rc = tipc_memref_prepare_aligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT, NULL,
                                     buf_size_);
    EXPECT_EQ(rc, -EINVAL);

    tipc_memref_finish(&mref, 0);

    /* bad size */
    rc = tipc_memref_prepare_aligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                     aligned_buf_, 0);
    EXPECT_EQ(rc, -EINVAL);

    tipc_memref_finish(&mref, 0);

    /* unaligned base address */
    rc = tipc_memref_prepare_aligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                     aligned_buf_ + 1, buf_size_);
    EXPECT_EQ(rc, -EINVAL);

    tipc_memref_finish(&mref, 0);

    /* unaligned size */
    rc = tipc_memref_prepare_aligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                     aligned_buf_, buf_size_ - 1);
    EXPECT_EQ(rc, -EINVAL);

    tipc_memref_finish(&mref, 0);
}

TEST_F(MRefAPITest, PrepareUnaligned) {
    int rc;
    size_t doff;
    size_t hsize;
    struct tipc_memref mref;

    pg_size_ = getpagesize();
    buf_size_ = 12 * pg_size_;
    rc = posix_memalign((void**)&aligned_buf_, pg_size_, buf_size_);
    ASSERT_EQ(rc, 0);

    /* whole aligned buffer */
    rc = tipc_memref_prepare_unaligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                       aligned_buf_, buf_size_, 0, buf_size_, &hsize, &doff);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(doff, 0);
    EXPECT_EQ(hsize, buf_size_);

    tipc_memref_finish(&mref, 0);

    /* partial buffer: head at page offset, tail at buffer end */
    rc = tipc_memref_prepare_unaligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                       aligned_buf_, buf_size_, pg_size_, buf_size_ - pg_size_,
                                       &hsize, &doff);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(doff, 0);
    EXPECT_EQ(hsize, buf_size_ - pg_size_);

    tipc_memref_finish(&mref, 0);

    /* partial buffer: head at page offset, tail at buffer end - page */
    rc = tipc_memref_prepare_unaligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                       aligned_buf_, buf_size_, pg_size_, buf_size_ - 2 * pg_size_,
                                       &hsize, &doff);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(doff, 0);
    EXPECT_EQ(hsize, buf_size_ - 2 * pg_size_);

    tipc_memref_finish(&mref, 0);

    /* unaligned head: head at offset 1, tail at buffer end */
    rc = tipc_memref_prepare_unaligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                       aligned_buf_ + 1, buf_size_, 0, buf_size_ - 1, &hsize,
                                       &doff);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(doff, 1);
    EXPECT_EQ(hsize, buf_size_);

    tipc_memref_finish(&mref, 0);

    /* unaligned head: head at offset page + 1, tail at buffer end */
    rc = tipc_memref_prepare_unaligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                       aligned_buf_, buf_size_, pg_size_ + 1,
                                       buf_size_ - pg_size_ - 1, &hsize, &doff);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(doff, 1);
    EXPECT_EQ(hsize, buf_size_ - pg_size_);

    tipc_memref_finish(&mref, 0);

    /* unaligned head: head at offset  page + 1 , tail at buffer end - page */
    rc = tipc_memref_prepare_unaligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                       aligned_buf_, buf_size_, pg_size_ + 1,
                                       buf_size_ - 2 * pg_size_ - 1, &hsize, &doff);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(doff, 1);
    EXPECT_EQ(hsize, buf_size_ - 2 * pg_size_);

    tipc_memref_finish(&mref, 0);

    /* unaligned tail: tail at buffer end - 1 */
    rc = tipc_memref_prepare_unaligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                       aligned_buf_, buf_size_ - 1, 0, buf_size_ - 1, &hsize,
                                       &doff);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(doff, 0);
    EXPECT_EQ(hsize, buf_size_);

    tipc_memref_finish(&mref, 0);

    /* unaligned tail: tail at buffer end - page - 1 */
    rc = tipc_memref_prepare_unaligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                       aligned_buf_, buf_size_, 0, buf_size_ - pg_size_ - 1, &hsize,
                                       &doff);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(doff, 0);
    EXPECT_EQ(hsize, buf_size_ - pg_size_);

    tipc_memref_finish(&mref, 0);

    /* unaligned head and tail */
    rc = tipc_memref_prepare_unaligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                       aligned_buf_ + 1, buf_size_ - 2, 0, buf_size_ - 2, &hsize,
                                       &doff);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(doff, 1);
    EXPECT_EQ(hsize, buf_size_);

    tipc_memref_finish(&mref, 0);

    /* unaligned head and tail: data head at page + 1, data tail at buffer end - page - 1  */
    rc = tipc_memref_prepare_unaligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                       aligned_buf_ + 1, buf_size_ - 2, pg_size_,
                                       buf_size_ - 2 * pg_size_ - 1, &hsize, &doff);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(doff, 1);
    EXPECT_EQ(hsize, buf_size_ - 2 * pg_size_);

    tipc_memref_finish(&mref, 0);
}

TEST_F(MRefAPITest, PrepareUnalignedNegative) {
    int rc;
    size_t doff;
    size_t hsize;
    struct tipc_memref mref;

    pg_size_ = getpagesize();
    buf_size_ = 12 * pg_size_;
    rc = posix_memalign((void**)&aligned_buf_, pg_size_, buf_size_);
    ASSERT_EQ(rc, 0);

    /* Invalid mref pointer */
    rc = tipc_memref_prepare_unaligned(NULL, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                       aligned_buf_, buf_size_, 0, buf_size_, &hsize, &doff);
    ASSERT_EQ(rc, -EINVAL);

    /* invalid data offset ptr */
    rc = tipc_memref_prepare_unaligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                       aligned_buf_, buf_size_, 0, buf_size_, NULL, &doff);
    ASSERT_EQ(rc, -EINVAL);

    /* invalid handle size ptr */
    rc = tipc_memref_prepare_unaligned(NULL, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                       aligned_buf_, buf_size_, 0, buf_size_, &hsize, NULL);
    ASSERT_EQ(rc, -EINVAL);

    /* Invalid data direction */
    rc = tipc_memref_prepare_unaligned(&mref, 0, aligned_buf_, buf_size_, 0, buf_size_, &hsize,
                                       &doff);
    EXPECT_EQ(rc, -EINVAL);

    tipc_memref_finish(&mref, 0);

    /* Invalid base address */
    rc = tipc_memref_prepare_unaligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT, NULL,
                                       buf_size_, 0, buf_size_, &hsize, &doff);
    EXPECT_EQ(rc, -EINVAL);

    tipc_memref_finish(&mref, 0);

    /* invalid (0) size */
    rc = tipc_memref_prepare_unaligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                       aligned_buf_, 0, 0, buf_size_, &hsize, &doff);
    EXPECT_EQ(rc, -EINVAL);

    tipc_memref_finish(&mref, 0);

    /* offset out of range */
    rc = tipc_memref_prepare_unaligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                       aligned_buf_, buf_size_, buf_size_, pg_size_, &hsize, &doff);
    EXPECT_EQ(rc, -EINVAL);

    tipc_memref_finish(&mref, 0);

    /* data size out of range */
    rc = tipc_memref_prepare_unaligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                       aligned_buf_, buf_size_, 0, buf_size_ + 1, &hsize, &doff);
    EXPECT_EQ(rc, -EINVAL);

    tipc_memref_finish(&mref, 0);
}

TEST_F(MRefAPITest, FinishAligned) {
    int rc;
    struct tipc_memref mref;

    pg_size_ = getpagesize();
    buf_size_ = 12 * pg_size_;
    rc = posix_memalign((void**)&aligned_buf_, pg_size_, buf_size_);
    ASSERT_EQ(rc, 0);

    /*  - set buffer to 0x55
     *  - call prepare aligned,
     *  - set buffer to 0xaa,
     *  - call finish
     *  - buffer should be set to 0xaa
     */
    memset(aligned_buf_, 0x55, buf_size_);
    rc = tipc_memref_prepare_aligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                     aligned_buf_, buf_size_);
    EXPECT_EQ(rc, 0);

    memset(aligned_buf_, 0xaa, buf_size_);
    tipc_memref_finish(&mref, buf_size_);

    rc = CheckBuffer(aligned_buf_, buf_size_, 0xaa);
    EXPECT_EQ(rc, 0);
}

TEST_F(MRefAPITest, FinishUnaligned) {
    int rc;
    size_t doff;
    size_t hsize;
    struct tipc_memref mref;

    pg_size_ = getpagesize();
    buf_size_ = 12 * pg_size_;
    rc = posix_memalign((void**)&aligned_buf_, pg_size_, buf_size_);
    ASSERT_EQ(rc, 0);

    /*  - set buffer to 0x55
     *  - call prepare analigned
     *  - set buffer to 0xaa,
     *  - call finish
     *  - buffer should be complicated
     */

    memset(aligned_buf_, 0x55, buf_size_);
    rc = tipc_memref_prepare_unaligned(&mref, TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT,
                                       aligned_buf_ + pg_size_ / 2, buf_size_ - pg_size_, 0,
                                       buf_size_ - pg_size_, &hsize, &doff);
    EXPECT_EQ(rc, 0);

    memset(aligned_buf_, 0xaa, buf_size_);

    tipc_memref_finish(&mref, buf_size_);

    rc = CheckBuffer(aligned_buf_, pg_size_ / 2, 0xaa);
    EXPECT_EQ(rc, 0);

    rc = CheckBuffer(aligned_buf_ + pg_size_ / 2, pg_size_ / 2, 0x55);
    EXPECT_EQ(rc, 0);

    rc = CheckBuffer(aligned_buf_ + pg_size_, buf_size_ - 2 * pg_size_, 0xaa);
    EXPECT_EQ(rc, 0);

    rc = CheckBuffer(aligned_buf_ + buf_size_ - pg_size_, pg_size_ / 2, 0x55);
    EXPECT_EQ(rc, 0);

    rc = CheckBuffer(aligned_buf_ + buf_size_ - pg_size_ / 2, pg_size_ / 2, 0xaa);
    EXPECT_EQ(rc, 0);
}

/*
 * Copyright (C) 2015-2017 The Android Open Source Project
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

#define LOG_TAG "libtrusty"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <log/log.h>
#include <trusty/tipc.h>

int tipc_connect(const char* dev_name, const char* srv_name) {
    int fd;
    int rc;

    fd = open(dev_name, O_RDWR);
    if (fd < 0) {
        rc = -errno;
        ALOGE("%s: cannot open tipc device \"%s\": %s\n", __func__, dev_name, strerror(errno));
        return rc < 0 ? rc : -1;
    }

    rc = ioctl(fd, TIPC_IOC_CONNECT, srv_name);
    if (rc < 0) {
        rc = -errno;
        ALOGE("%s: can't connect to tipc service \"%s\" (err=%d)\n", __func__, srv_name, errno);
        close(fd);
        return rc < 0 ? rc : -1;
    }

    ALOGV("%s: connected to \"%s\" fd %d\n", __func__, srv_name, fd);
    return fd;
}

int tipc_close(int fd) {
    return close(fd);
}

int tipc_send_msg(int fd, const struct iovec* iov, unsigned int iov_cnt,
                  const struct tipc_memref* mrefv, unsigned int mrefv_cnt) {
    unsigned int i;

    struct tipc_send_msg_req msg;
    struct tipc_shmem shmemv[TIPC_MAX_MEMREF_NUM];

    if (mrefv_cnt > TIPC_MAX_MEMREF_NUM) {
        /* too many MEMREFs  */
        return -EINVAL;
    }

    for (i = 0; i < mrefv_cnt; i++) {
        shmemv[i] = mrefv[i].shmem;
    }

    msg.msgiov = (__u64)(uintptr_t)iov;
    msg.msgiov_cnt = iov_cnt;
    msg.shmemv = (__u64)(uintptr_t)shmemv;
    msg.shmemv_cnt = mrefv_cnt;

    return ioctl(fd, TIPC_IOC_SEND_MSG, &msg);
}

int tipc_recv_msg(int fd, const struct iovec* iov, unsigned int iov_cnt) {
    return readv(fd, iov, iov_cnt);
}

/*
 * Helper functions to manupulate memrefs
 */

#define ROUNDDN(v, a) ((uintptr_t)(v) & ~((uintptr_t)(a)-1))
#define ROUNDUP(v, a) ROUNDDN((v) + ((uintptr_t)(a)-1), (a))

/*
 *  Validate memref paramters
 */
static int memref_validate(struct tipc_memref* mr, bool aligned) {
    if (!mr->shr_base) {
        /* there should be a base addr */
        return -EINVAL;
    }

    if (!mr->page_size || (mr->page_size & (mr->page_size - 1))) {
        /* page_size should be non zero and power of 2 */
        return -EINVAL;
    }

    if (!mr->data_size || !mr->shr_size) {
        /* sizes should not be 0 */
        return -EINVAL;
    }

    if ((mr->shmem.flags & (TIPC_MEMREF_DATA_IN | TIPC_MEMREF_DATA_OUT)) == 0) {
        /* no data direction specified */
        return -EINVAL;
    }

    if (aligned) {
        /* sharable region has to be page aligned */
        if (mr->shr_base & (mr->page_size - 1)) {
            return -EINVAL;
        }

        if (mr->shr_size & (mr->page_size - 1)) {
            return -EINVAL;
        }
    }

    if ((mr->data_off > mr->shr_size) || (mr->data_size > mr->shr_size) ||
        ((mr->shr_size - mr->data_off) < mr->data_size)) {
        /* data offset and size should be within sharable region */
        return -EINVAL;
    }

    return 0;
}

/*
 * Initialize memref structure and do paramater checks
 */
static int memref_init(struct tipc_memref* mr, uint32_t flags, void* shr_base, size_t shr_size,
                       size_t data_off, size_t data_size, bool aligned) {
    int rc;

    memset(mr, 0, sizeof(*mr));

    mr->shr_base = (uintptr_t)shr_base;
    mr->shr_size = shr_size;
    mr->data_off = data_off;
    mr->data_size = data_size;
    mr->page_size = getpagesize();
    mr->shmem.flags = flags;

    /* validate parameters */
    rc = memref_validate(mr, aligned);
    if (rc) {
        return rc;
    }

    return 0;
}

/*
 *
 * Reduce the size of the region we have to expose to Trusty to the minimum.
 * Calculate amount of extra memory that will be required to complete exchange.
 */
static uint32_t recalc_shr_region(struct tipc_memref* mr) {
    uintptr_t shr_beg;
    uintptr_t shr_end;
    uintptr_t data_beg;
    uintptr_t shrink_beg;
    unsigned int pgcnt = 0;

    /*
     * This function assumes that region sanity had been checked
     * by prior memref_validate call
     */

    /* page align base of sharable region base if possible */
    data_beg = mr->shr_base + mr->data_off;
    shr_beg = ROUNDDN(data_beg, mr->page_size);
    if (shr_beg < mr->shr_base) {
        /* set it to the start of the data region */
        shr_beg = data_beg;
    }

    /* shrink beg */
    shrink_beg = shr_beg - mr->shr_base;
    mr->data_off -= shrink_beg;
    mr->shr_size -= shrink_beg;
    mr->shr_base += shrink_beg;

    assert(mr->shr_base == shr_beg);

    /* page align end of shareable region if possible */
    shr_end = ROUNDUP(data_beg + mr->data_size, mr->page_size);
    if (shr_end > shr_beg + mr->shr_size) {
        /* set it to the end of the data region */
        shr_end = data_beg + mr->data_size;
    }
    mr->shr_size = shr_end - shr_beg;

    /*
     * calculate number of additional pages we will need. We will need 1 extra page
     * per unaligned end unless both ends are unaligned and on the same page.
     * In later case we will only need 1 page instead of 2.
     */
    if (shr_beg & (mr->page_size - 1)) {
        /* head is unaligned, 1 extra page is required */
        pgcnt++;
    }
    if (shr_end & (mr->page_size - 1)) {
        /* tail is unaligned, 1 extra page is required */
        pgcnt++;
    }

    if (pgcnt == 2 && ROUNDDN(shr_beg, mr->page_size) == ROUNDDN(shr_end - 1, mr->page_size)) {
        /* both ends are on the same page, only 1 page is required */
        pgcnt = 1;
    }

    return pgcnt;
}

/**
 * tipc_memref_prepare_aligned() - initialize with aligned shareable region
 * @mr:         points to &struct tipc_memref to initialize
 * @flags:      a combination of TIPC_MEMREF_XXX flags indicating data flow
 *              direction
 * @shr_base:   base address of the memory region that is allowed to be exposed
 *              to Trusty
 * @shr_size:   size of the memory region that is allowed to be exposed to
 *              Trusty
 *
 * Shareable data region must be page aligned.
 *
 * Return: 0 on success negative value on error.
 */
int tipc_memref_prepare_aligned(struct tipc_memref* mr, uint32_t flags, void* shr_base,
                                size_t shr_size) {
    int rc;

    if (!mr) {
        return -EINVAL;
    }

    rc = memref_init(mr, flags, shr_base, shr_size, 0, shr_size, true);
    if (rc < 0) {
        return rc;
    }

    mr->shmem.rgns[0].base = (uintptr_t)mr->shr_base;
    mr->shmem.rgns[0].size = mr->shr_size;

    return 0;
}

/**
 * tipc_memref_prepare_unaligned() - initialize with potentially unaligned
 * shareable region
 * @mr:         points to &struct tipc_memref to initialize
 * @flags:      a combination of TIPC_MEMREF_XXX flags indicating data flow
 *              direction
 * @shr_base:   base address of the memory region which content is allowed to
 *              be exposed to Trusty
 * @shr_size:   size of the memory region which content is allowed to be
 *              exposed to Trusty
 * @data_off:   offset of data region relative to @shr_base
 * @data_size:  size of data region
 * @phsize:     points to location to place handle size that needs to be send
 *              to Trusty along with specified &struct tipc_memref pointed by
 *              @mr parameter
 * @phoff:      points to location to place data offset that needs to be send
 *              to Trusty along with specified &struct tipc_memref pointed by
 *              @mr parameter
 *
 * Shareable data region should be at least as large as data region but could
 * be wider. Page aligning is strongly recommended.
 *
 * Return: 0 on success negative value on error.
 */
int tipc_memref_prepare_unaligned(struct tipc_memref* mr, uint32_t flags, void* shr_base,
                                  size_t shr_size, size_t data_off, size_t data_size,
                                  size_t* phsize, size_t* phoff) {
    int rc;
    size_t pos;
    uintptr_t beg;
    uintptr_t end;
    uint8_t* cur_page;

    if (!mr || !phsize || !phoff) {
        return -EINVAL;
    }

    /* initialize memref object */
    rc = memref_init(mr, flags, shr_base, shr_size, data_off, data_size, false);
    if (rc < 0) {
        return rc;
    }

    /* reduce sharable region size to minimum and calculate amout of additional memory to
     * do exchange.
     */
    mr->aux_page_cnt = recalc_shr_region(mr);
    if (mr->aux_page_cnt) {
        /* Allocate extra memory needed */
        rc = posix_memalign(&mr->aux_pages, mr->page_size, mr->aux_page_cnt * mr->page_size);
        if (rc) {
            return -ENOMEM;
        }
        cur_page = mr->aux_pages;
    }

    beg = (uintptr_t)mr->shr_base;
    end = (uintptr_t)mr->shr_base + mr->shr_size;

    if (ROUNDDN(beg, mr->page_size) == ROUNDDN(end - 1, mr->page_size)) {
        /* region ends are on the same page */
        if (mr->shr_size == mr->page_size) {
            /* the whole page is sharable; no copy is required */
            mr->shmem.rgns[1].size = mr->page_size;
            mr->shmem.rgns[1].base = (__u64)(uintptr_t)mr->shr_base;
            *phoff = mr->data_off;
        } else {
            /* page is partially sharable */
            *phoff = pos = (beg + mr->data_off) & (mr->page_size - 1);

            memset(cur_page, 0, pos);
            memcpy(cur_page + pos, (void*)(mr->shr_base + mr->data_off), mr->data_size);
            pos += mr->data_size;
            memset(cur_page + pos, 0, mr->page_size - pos);

            mr->shmem.rgns[0].size = mr->page_size;
            mr->shmem.rgns[0].base = (__u64)(uintptr_t)cur_page;
            cur_page += mr->page_size;
        }
        *phsize = mr->page_size;
        return 0;
    }

    /* handle buffer head */
    pos = beg & (mr->page_size - 1);
    if (pos) {
        /*
         * if head is unaligned it has to point to the start of data region
         * so data_off must be 0
         */
        assert(!mr->data_off);
        memset(cur_page, 0, pos);
        memcpy(cur_page + pos, (const void*)beg, mr->page_size - pos);
        mr->shmem.rgns[0].size = mr->page_size;
        mr->shmem.rgns[0].base = (__u64)(uintptr_t)cur_page;
        cur_page += mr->page_size;
        beg += mr->page_size - pos;
        *phoff = pos;
    } else {
        /* head is aligned */
        assert(mr->data_off < mr->page_size);
        *phoff = mr->data_off;
    }

    /* handle buffer tail */
    pos = end & (mr->page_size - 1);
    if (pos) {
        /* tail is unaligned it must point to the end of the data region */
        end -= pos;
        memcpy(cur_page, (const void*)end, pos);
        memset(cur_page + pos, 0, mr->page_size - pos);
        mr->shmem.rgns[2].size = mr->page_size;
        mr->shmem.rgns[2].base = (__u64)(uintptr_t)cur_page;
        cur_page += mr->page_size;
    }

    /* setup middle region */
    mr->shmem.rgns[1].size = (__u64)(end - beg);
    mr->shmem.rgns[1].base = (__u64)(uintptr_t)beg;

    /* calculate handle size */
    *phsize = mr->shmem.rgns[0].size + mr->shmem.rgns[1].size + mr->shmem.rgns[2].size;

    return 0;
}

/**
 * tipc_memref_finish() - indicate that data exchange have been completed
 * @mr:   points to &struct tipc_memref previously initialized with
 *        tipc_memref_prepare_aligned()/tipc_memref_prepare_unaligned() calls
 * @size: number of bytes updated in target buffer. This value will be used in
 *        some cases to sync data back to original destination
 *
 * Note 1: For each tipc_memref_finish() call made there must be matching
 * tipc_memref_prepare_aligned()/tipc_memref_prepare_unaligned() call.
 *
 * Note 2: If the caller prepared structure pointed by @mr parameter using
 * tipc_memref_prepare_unaligned() call and data specified flow direction has
 * contained TIPC_MEMREF_DATA_IN flag, it is not guaranteed that data received
 * will be consistent in original buffer until this call has been made.

 * Note 3: If an additional memory has been internally allocated by
 * tipc_memref_prepare_unaligned() call, it will be freed by this call.
 *
 * Return: none
 */
void tipc_memref_finish(struct tipc_memref* mr, size_t size) {
    uint i;
    size_t offset;
    size_t to_sync;
    uint8_t* dst;

    assert(mr);

    if (!mr->aux_page_cnt) {
        /* nothing to do here */
        goto invalidate;
    }

    if (size > mr->data_size) size = mr->data_size;

    if ((mr->shmem.flags & TIPC_MEMREF_DATA_IN) && size) {
        /* we might need to do sync here */
        dst = (uint8_t*)mr->shr_base + mr->data_off;
        offset = (mr->shr_base + mr->data_off) & (mr->page_size - 1);

        /* for all segments */
        for (i = 0; i < 3; i++) {
            if (offset >= mr->shmem.rgns[i].size) { /* skip the whole segment */
                offset -= mr->shmem.rgns[i].size;
                continue;
            }

            /* calc how much data to copy/skip in this segment */
            to_sync = mr->shmem.rgns[i].size - offset;
            if (to_sync > size) to_sync = size;

            /* we only need to actually copy segments 0 and 2 */
            if (i != 1) memcpy(dst, (const void*)(mr->shmem.rgns[i].base + offset), to_sync);

            size -= to_sync;
            if (!size) return;

            offset = 0;
            dst = (uint8_t*)dst + to_sync;
        }
    }

    if (mr->aux_pages) {
        /* we are tracking extra pages, free them */
        free(mr->aux_pages);
        mr->aux_pages = NULL;
        mr->aux_page_cnt = 0;
    }

invalidate:
    /* invalidate tipc_shmem struct so underlying object cannot be send again
     * without calling prfepare first.
     */
    mr->shmem.flags = 0;
}

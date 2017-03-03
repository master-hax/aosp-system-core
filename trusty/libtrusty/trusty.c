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

int tipc_connect(const char *dev_name, const char *srv_name)
{
    int fd;
    int rc;

    fd = open(dev_name, O_RDWR);
    if (fd < 0) {
        rc = -errno;
        ALOGE("%s: cannot open tipc device \"%s\": %s\n", __func__, dev_name,
              strerror(errno));
        return rc < 0 ? rc : -1;
    }

    rc = ioctl(fd, TIPC_IOC_CONNECT, srv_name);
    if (rc < 0) {
        rc = -errno;
        ALOGE("%s: can't connect to tipc service \"%s\" (err=%d)\n", __func__,
              srv_name, errno);
        close(fd);
        return rc < 0 ? rc : -1;
    }

    ALOGV("%s: connected to \"%s\" fd %d\n", __func__, srv_name, fd);
    return fd;
}

int tipc_close(int fd)
{
    return close(fd);
}

int tipc_send_msg(int fd, const struct iovec *iov, unsigned int iov_cnt,
                  const struct tipc_memref *mrefv, unsigned int mrefv_cnt)
{
    unsigned int i;

    struct tipc_send_msg_req msg;
    struct tipc_shmem shmemv[mrefv_cnt];

    for (i = 0; i < mrefv_cnt; i++)
        shmemv[i] = mrefv[i].shmem;

    msg.msgiov = (__u64)(uintptr_t)iov;
    msg.msgiov_cnt = iov_cnt;
    msg.shmemv = (__u64)(uintptr_t)shmemv;
    msg.shmemv_cnt = mrefv_cnt;

    return ioctl(fd, TIPC_IOC_SEND_MSG, &msg);
}

int tipc_recv_msg(int fd, const struct iovec *iov, unsigned int iov_cnt)
{
    return readv(fd, iov, iov_cnt);
}

/* Helper functions to manupulate memrefs */

#define ROUNDDN(v, a) ((v) & ~((a)-1))
#define ROUNDUP(v, a) (((v) + (a) + 1) & ~((a)-1))

static int validate_params(struct tipc_memref *mr)
{
    if (!mr->shr_base)
        return -EINVAL;

    if (!mr->page_size || (mr->page_size & (mr->page_size - 1)))
        return -EINVAL;

    if (!mr->data_size)
        return -EINVAL;

    if ((mr->data_off > mr->shr_size) || (mr->data_size > mr->shr_size) ||
        ((mr->shr_size - mr->data_off) < mr->data_size))
        return -EINVAL;

    return 0;
}

static uint32_t _calk_aux_mem(struct tipc_memref *mr)
{
    uintptr_t shr_beg;
    uintptr_t shr_end;
    uint pgcnt = 0;

    if (!mr->data_size)
        return 0;

    /* page align sharable region base if possible */
    shr_beg = ROUNDDN(mr->shr_base + mr->data_off, mr->page_size);
    if (shr_beg < mr->shr_base) {
        /* set it to the start of the data region */
        shr_beg = mr->shr_base + mr->data_off;
    }
    mr->data_off -= shr_beg - mr->shr_base;
    mr->shr_size -= shr_beg - mr->shr_base;
    mr->shr_base = shr_beg;

    /* page align sharable region end if possible */
    shr_end = ROUNDUP(shr_beg + mr->data_off + mr->data_size, mr->page_size);
    if (shr_end > shr_beg + mr->shr_size) {
        /* set it to the end of the data region */
        shr_end = shr_beg + mr->data_off + mr->data_size;
    }
    mr->shr_size -= shr_beg + mr->shr_size - shr_end;

    if (ROUNDDN(shr_beg, mr->page_size) == ROUNDDN(shr_end - 1, mr->page_size)) {
        if (mr->shr_size == mr->page_size)
            return 0;
        else
            return 1;
    } else {
        if (shr_beg & (mr->page_size - 1))
            pgcnt++;

        if (shr_end & (mr->page_size - 1))
            pgcnt++;
    }
    return pgcnt;
}

int tipc_memref_init(struct tipc_memref *mr, uint32_t flags,
                     const void *shr_base, uint32_t shr_size,
                     uint32_t data_size, uint32_t data_off, uint32_t page_size)
{
    int rc;

    if (!mr)
        return -EINVAL;

    memset(mr, 0, sizeof(*mr));

    mr->shr_base = (uintptr_t)shr_base;
    mr->shr_size = shr_size;
    mr->data_off = data_off;
    mr->data_size = data_size;
    mr->page_size = page_size;
    mr->shmem.flags = flags;

    /* validate parameters */
    rc = validate_params(mr);
    if (rc)
        return rc;

    return _calk_aux_mem(mr);
}

void tipc_memref_prepare(struct tipc_memref *mr, uint32_t *phsize,
                         uint32_t *phoff, void **aux_pages)
{
    uint32_t pos;
    uintptr_t beg;
    uintptr_t end;

    assert(mr);
    assert(phsize);
    assert(phoff);

    beg = (uintptr_t)mr->shr_base;
    end = (uintptr_t)mr->shr_base + mr->shr_size;

    if (ROUNDDN(beg, mr->page_size) == ROUNDDN(end - 1, mr->page_size)) {
        /* shrable region ends are on the same page */
        if (mr->shr_size == mr->page_size) {
            /* the whole page is sharable; no copy */
            mr->shmem.size[1] = mr->page_size;
            mr->shmem.base[1] = (__u64)(uintptr_t)mr->shr_base;
            *phoff = mr->data_off;
        } else {
            /* page is partially sharable */
            *phoff = pos = (beg + mr->data_off) & (mr->page_size - 1);

            memset(*aux_pages, 0, pos);
            memcpy((uint8_t *)*aux_pages + pos,
                   (void *)(mr->shr_base + mr->data_off), mr->data_size);
            pos += mr->data_size;
            memset((uint8_t *)*aux_pages + pos, 0, mr->page_size - pos);

            mr->shmem.size[0] = mr->page_size;
            mr->shmem.base[0] = (__u64)(uintptr_t)*aux_pages;
            *aux_pages = (uint8_t *)*aux_pages + mr->page_size;
        }
        *phsize = mr->page_size;
        return;
    }

    /* handle head */
    pos = beg & (mr->page_size - 1);
    if (pos) {
        /* is only possible if data_off is 0 */
        memset(*aux_pages, 0, pos);
        memcpy((uint8_t *)*aux_pages + pos, (const void *)beg,
               mr->page_size - pos);
        mr->shmem.size[0] = mr->page_size;
        mr->shmem.base[0] = (__u64)(uintptr_t)*aux_pages;
        *aux_pages = (uint8_t *)*aux_pages + mr->page_size;
        beg += mr->page_size - pos;
        *phoff = pos;
    } else {
        /* head is aligned */
        *phoff = mr->data_off;
    }

    /* handle tail */
    pos = end & (mr->page_size - 1);
    if (pos) {
        /* is only possible if end points to end of the data region */
        end -= pos;
        memcpy(*aux_pages, (const void *)end, pos);
        memset((uint8_t *)*aux_pages + pos, 0, mr->page_size - pos);
        mr->shmem.size[2] = mr->page_size;
        mr->shmem.base[2] = (__u64)(uintptr_t)*aux_pages;
        *aux_pages = (uint8_t *)*aux_pages + mr->page_size;
    }

    mr->shmem.size[1] = (__u32)(end - beg);
    mr->shmem.base[1] = (__u64)(uintptr_t)beg;

    *phsize = mr->shmem.size[0] + mr->shmem.size[1] + mr->shmem.size[2];
}

/*
 *  Sync back memref range
 */
void tipc_memref_finish(const struct tipc_memref *mr, uint32_t size)
{
    uint i;
    uint32_t offset;
    uint32_t to_sync;
    uint8_t *dst;

    assert(mr);

    if (!(mr->shmem.flags & TIPC_MEMREF_PERM_RW))
        return; /* nothing needs to be done for read only memref */

    dst = (uint8_t *)mr->shr_base + mr->data_off;
    offset = (mr->shr_base + mr->data_off) & (mr->page_size - 1);

    /* for all segments */
    for (i = 0; i < 3; i++) {
        if (offset >= mr->shmem.size[i]) { /* skip the whole segment */
            offset -= mr->shmem.size[i];
            continue;
        }

        /* calc how much data to copy/skip in this segment */
        to_sync = mr->shmem.size[i] - offset;
        if (to_sync > size)
            to_sync = size;

        /* we only need to actually copy segments 0 and 2 */
        if (i != 1)
            memcpy(dst, (const void *)(mr->shmem.base[i] + offset), to_sync);

        size -= to_sync;
        if (!size)
            return;

        offset = 0;
        dst = (uint8_t *)dst + to_sync;
    }
}

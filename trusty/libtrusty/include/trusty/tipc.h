/*
 * Copyright (C) 2015-2019 The Android Open Source Project
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

#ifndef _LIB_TIPC_H
#define _LIB_TIPC_H

#include <stdint.h>
#include <sys/uio.h>
#include <trusty/trusty_ipc_ioctl.h>

#ifdef __cplusplus
extern "C" {
#endif

int tipc_connect(const char* dev_name, const char* srv_name);
int tipc_close(int fd);

/*
 * Helper functions to handle memory references
 */

/**
 * DOC: Theory of operation
 *
 * Memory references facilitate a way to exchange relatively large amount of
 * data between non-secure user process and a service running within Trusty.
 *
 * The primary goal for this implementation is to support "synchronous" calls
 * into Trusty (each request assume there will be a reply) and provide a way
 * to pass relatively large amount of data local to the calling process while
 * minimizing data copying required and providing strict and explicit control
 * over data that are exposed to Trusty. In this implementation a temporary
 * memory sharing will be established between calling process and target
 * service running in Trusty. If data buffers are properly aligned and
 * organized a zero copy exchange can be achieved. Memory is shared in page
 * quantities so it is strongly recommended that both source and target buffers
 * should be page aligned. Sharing unaligned buffers is also supported but
 * would require extra memory and partial content copy in some cases.
 *
 * The following description represents a typical sequence of calls to pass
 * memref to service running in Trusty:
 *
 *  - call tipc_memref_prepare_XXXX to initialize memref tracking structure.
 * A caller has to provide a data flow direction, a memory region content of
 * which is allowed to be shared with Trusty for this operation and a location
 * of actual data buffer within that region. Only data within specified
 * shareable region are allowed to be exposed to Trusty during memref
 * operation. A specified shareable region has to at least envelop target data
 * buffer and if it is  big enough to accommodate the whole number of pages a
 * direct memory sharing can be performed and zero copy sharing can be
 * achieved. If caller is paranoid and specified shareable data buffer is not
 * big enough to accommodate the whole number of pages enveloping target data
 * buffer, a partial page copying has to happen and up to 2 pages (depending on
 * alignment) of additional memory will be allocated to safely complete data
 * exchange without having undesired data exposure. In this case the content of
 * pages that needs to be partially shared will be moved to these newly
 * allocated pages, the leftover space will be sanitized and these new pages
 * will be actually shared instead of original once. Since
 * tipc_memref_prepare_aligned call only accepts page aligned shareable region,
 * it is impossible to get into the situation where additional memory will be
 * required and zero copy sharing will be achieved.
 *
 * - call tipc_send_msg to transmit message accompanied by one or more memrefs
 * descriptors to Trusty. Up to 8 memref descriptors can be specified. On the
 * receiving side each memref will be converted into a memory handle and can be
 * mapped into the target application's address space. The accompanied message
 * itself has to contain certain additional information about each memref as
 * such info in not recoverable on Trusty side from the handle itself. It
 * should at least contain handle size, data offset, data size, and data flow
 * direction. All this information is either known by the caller or provided by
 * tipc_memref_prepare call.
 *
 * - call tipc_read_msg to wait and read reply from Trusty.
 *
 * - call tipc_memref_finish to indicate that data exchange has been completed
 * and all data, if copied, needs to be synced back to original location. This
 * is complementary to tipc_memref_prepare and has to be performed if
 * tipc_memref_prepare was successful.
 */

/**
 * struct tipc_memref - structure to represent memory reference on client side
 *
 * All members of this structure should be treated as private by caller.
 */
struct tipc_memref {
    /* private: internal use only */
    uintptr_t shr_base;
    size_t shr_size;
    size_t data_off;
    size_t data_size;
    uint32_t page_size;
    uint32_t aux_page_cnt;
    void* aux_pages;
    struct tipc_shmem shmem;
};

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
                                size_t shr_size);

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
                                  size_t* phsize, size_t* phoff);

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
void tipc_memref_finish(struct tipc_memref* mr, size_t size);

/**
 * tipc_send_msg() - sends specified message over specified TIPC channel
 * @fd:        TIPC channel fd previously returned by tipc_connect() call
 * @iov:       points to &struct iovec array describing message to be send
 * @iov_cnt:   number of items in &struct iovec array pointed by @iov parameter
 * @mrefv:     points to &struct tipc_memref array describing memory references
 *             that needs to accompany message to be send
 * @mrefv_cnt: number of entries in &struct tipc_memref array pointed by @mrefv
 *             parameter
 *
 * Note 1: if @mrefv and @mrefv_cnt are set to 0, this call is functionally
 * equivalent to writev() for the same file descriptor.
 *
 * Return: a number of bytes sent on success, negative error code otherwise.
 */
int tipc_send_msg(int fd, const struct iovec* iov, unsigned int iov_cnt,
                  const struct tipc_memref* mrefv, unsigned int mrefv_cnt);

/**
 * tipc_recv_msg() - receives incoming message over specified TIPC channel
 * @fd:     TIPC channel fd previously returned by tipc_connect() call
 * @iov:    points to &struct iovec array describing buffer to store received
 *          massage
 * @iovcnt: number of entries in &struct iovec array pointed by @iov parameter
 *
 * Note 1: this call is functionally equivalent of calling readv() for the same
 * file descriptor.
 *
 * Return: total number of bytes placed into receiving buffers on success,
 * negative err code otherwise.
 */
int tipc_recv_msg(int fd, const struct iovec* iov, unsigned int iovcnt);

#ifdef __cplusplus
}
#endif

#endif

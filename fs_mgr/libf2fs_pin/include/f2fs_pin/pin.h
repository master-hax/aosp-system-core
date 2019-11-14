/*
 * Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <android-base/result.h>
#include <string>

//  The APIs in the android::f2fs_pin namespace are:
//
//  - BdevFileSystemSupportsReliablePinning() to determine if the file system mounted on a block
//    device supports reliable pinning through the FileAllocateSpaceAndReliablyPin() API;
//  - FileAllocateSpaceAndReliablyPin() to allocate space to a file and reliably pin it; and
//  - FileEnsureReliablyPinned() to determine if a file is reliably pinned.
//
//  Not every file created on an F2FS filesystem,and pinned via the I/O control operation to
//  pin a file, is reliably pinned.  F2FS in its space reclamation process (aka garbage collection)
//  will eventually unpin files storage blocks are not 100% made of fully allocated 2MB F2FS file
//  system segments.
//
//  To be able to reliably create files on an F2FS filesystem, the space for the file must be
//  allocated through the FileAllocateSpaceAndReliablyPin() API, underlying file system operations
//  that allocate space to the file must not be used.
//
//  This code is provided, isolated in its own namespace, to encapsulate these interfaces and hide
//  their implementation details.
//
//  There is disparate, unrelated code, in Android that requires access to this functionality.
//  Instead of coupling this code with various other code, it is purposely stand-alone so that
//  it can be reused more easily.
//
//  Concerns are kept separate between this code and the code that uses the API:
//      FileAllocateSpaceAndReliablyPin()
//  The file name, its creation, error handling related to its creation, its protection, and
//  any other aspects not important to the work of the API are all concerns that are left up
//  to the user of these APIs.
//
//  WARNING:
//      For a file to remain reliably pinned, its storage space must NOT be manipulated
//      in any way, either directly with fallocate(2) or ftruncate(2); or through writes
//      that make the file bigger.
//
//  For extra reliability, code that depends on reliably pinned files should verify after doing
//  whatever work needs to be done with the file (for example after it finishes writing data into
//  it), and immediately prior to closing its file desriptor, that the file is still realibly
//  pinned by calling:
//      FileEnsureReliablyPinned().

namespace android::f2fs_pin {

typedef android::base::Result<void> Result;

//  To be able to reliably pin files on F2FS their size must be a multiple of kF2fsSegmentSize.

constexpr off_t kF2fsSegmentSize = 2 * 1024 * 1024;

//  Does the file system mounted on the block device support reliable pinning through
//  the FileAllocateSpaceAndReliablyPin() API?
//
//  - bdev_name is the absolute pathname of the block device
//
//  The file system must be mounted on the device at the time the API is called.
//
//  If it supports reliable pinning, the API succeeds.
//  If it does not support reliable pinning the API fails.
//
//  Reliable pinning is a concept that only applies to the F2FS filesystem, if the file
//  system mounted on the block device is not an F2FS filesystem an error is returned.
//
//  If the filesystem mounted on the device is an F2FS filesystem but the F2FS kernel version
//  does not support reliably pinning, because it does not contain the patches that support
//  the feature, an error is returned.  The lack of support is determined by the absence of
//  the "main_blkaddr" file for the block device under "/sys/fs/f2fs"

Result BdevFileSystemSupportsReliablePinning(const std::string& bdev_name);

//  Allocate size bytes of file space to file_fd and reliably pin it, the success of the
//  operation is indicated by its result.
//
//  - file_fd must be a read/write file descriptor for a zero length regular file
//  - bdev_fd is a file descriptor for the block device that contains the file
//    system that contains the file
//  - bdev_name is the absolute pathname of the block device
//  - size is the amount of space in bytes that should be allocated, size must be
//    a multiple of kF2fsSegmentSize

Result FileAllocateSpaceAndReliablyPin(int file_fd, int bdev_fd, const std::string& bdev_name,
                                       off_t size);

//  Ensure that the file is reliably pinned, if it is not reliably pinned the results is a
//  failure result.
//
//  - file_fd must be a readable file descriptor for the regular file
//  - bdev_fd is a file descriptor for the block device that contains the file
//    system that contains the file
//  - bdev_name is the absolute pathname of the block device

Result FileEnsureReliablyPinned(int file_fd, int bdev_fd, const std::string& bdev_name);
};  // namespace android::f2fs_pin

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

#include <string>

//  The APIs in the android::pin namespace are:
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
//  allocated through the FileAllocateSpaceAndReliablyPin() API, underlyin file system operations
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

namespace android::pin {

//  To be able to reliably pin files on F2FS their size must be a multiple of kF2fsSegmentSize.

constexpr off_t kF2fsSegmentSize = 2 * 1024 * 1024;

//  The APIs BdevFileSystemSupportsReliablePinning(), FileAllocateSpaceAndReliablyPin() and
//  FileEnsureReliablyPinned() return a value of type Result.
//
//  Result faciliates the separation of concerns between this code and code that uses these
//  APIs. The APIs don't have to be sprinkled with error logging on behalf of its callers.
//  Not all users of APIs want error logging, their error handling might be of a different
//  nature. Thus error reporting and error logging or any other form of error handling are
//  best kept separate from this code. For example, test code, when testing for expected error
//  conditions does not want some extraneous error logging to occur.
//
//  Result is an opaque type, if IsError() is true, then an error occurred. If it is false,
//  the operation succeeded.
//
//  Result values might contain a Linux error number (errno), which should be obtained by
//  calling the GetErrno() member function on the result, if the value is non-zero, strerror(3)
//  or a similar function should be be used to obtain an appropriate error string for the Linux
//  error number.
//
//  A result value also encapsulates a description of the error and the function name,
//  declaration scope, file name, and line number where the error was detected.
//
//  For a result that indicates an error, i.e. one for which IsError() is true, statically
//  allocated constant C strings can be otained from the result through the following member
//  functions, the memory for these strings, of course, should not be deallocated:
//      GetDescription()   description of the error
//      GetFunction()      value of __func__               e.g. "AllocateSpaceAndReliablyPin"
//      GetScope()         declaration scope of __func__   e.g. "android::pin"
//      GetFile()          value of __FILE__
//
//  The line number within the function it detected the error is returned by:
//      GetLine()          value of __LINE__
//
//  A Result is made of a pointer (values_) and an integer (errno_).
//
//  Note that there is no dynamic memory allocation associated with Result objects, they are
//  strictly values. Purposely, by including only two register fitting values in Result values
//  the cost of the Result abstraction is minimal (all computer architectures implement the
//  return of Result values by returning them in two CPU registers).
//
//  The constant values (description, function, scope, file, and line number) associated with
//  a Result are found indirectly through the values_ pointer.

class ResultValues;
extern ResultValues result_values_no_error;

class Result {
  private:
    const ResultValues* values_;
    int errno_;

  public:
    Result() {
        values_ = &result_values_no_error;
        errno_ = 0;
    }
    Result(ResultValues* values, int error_number = 0) {
        values_ = values;
        errno_ = error_number;
    }
    bool IsError() { return values_ != &result_values_no_error; }
    int GetErrno() { return errno_; }
    const char* GetDescription();
    const char* GetFunction();
    const char* GetScope();
    const char* GetFile();
    int GetLine();
};

//  Does the file system mounted on the block device support reliable pinning through
//  the FileAllocateSpaceAndReliablyPin() API?
//
//  - bdev_name is the absolute pathname of the block device
//
//  The file system must be mounted on the device at the time the API is called.
//
//  If it supports reliable pinning, the API succeeds, IsError() on the Result is false.
//  If it does not support reliable pinning IsError() on the Result is true.
//
//  Reliable pinning is a concept that only applies to the F2FS filesystem, if the file
//  system mounted on the block device is not an F2FS filesystem an error is returned.
//
//  If the filesystem mounted on the device is an F2FS filesystem but the F2FS kernel version
//  does not support reliably pinning, because it does not contain the patches that support
//  the feature, an error is returned.  The lack of support is determined by the absence of
//  the "main_blkaddr" file for the block device under "/sys/fs/f2fs"

Result BdevFileSystemSupportsReliablePinning(std::string& bdev_name);

//  Allocate size bytes of file space to file_fd and reliably pin it.  If the operation
//  fails, IsError() will be true for the Result value.
//
//  - file_fd must be a read/write file descriptor for a zero length regular file
//  - bdev_fd is a file descriptor for the block device that contains the file
//    system that contains the file
//  - bdev_name is the absolute pathname of the block device
//  - size is the amount of space in bytes that should be allocated, size must be
//    a multiple of kF2fsSegmentSize

Result FileAllocateSpaceAndReliablyPin(int file_fd, int bdev_fd, std::string& bdev_name,
                                       off_t size);

//  Ensure that the file is reliably pinned, if it is not reliably pinned its Result value
//  will be an error (i.e. IsError() on it will be true).
//
//  - file_fd must be a readable file descriptor for the regular file
//  - bdev_fd is a file descriptor for the block device that contains the file
//    system that contains the file
//  - bdev_name is the absolute pathname of the block device

Result FileEnsureReliablyPinned(int file_fd, int bdev_fd, std::string& bdev_name);
};  // namespace android::pin

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
 * See the License for the specic language governing permissions and
 * limitations under the License.
 */

#include "libappfuse/FuseAppLoop.h"

#include <sys/stat.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>

namespace android {

void FuseAppLoop::HandleLookUp(FuseAppLoop::Callback* callback) {
  // AppFuse does not support directory structure now.
  // It can lookup only files under the mount point.
  if (buffer_.request.header.nodeid != FUSE_ROOT_ID) {
    LOG(ERROR) << "Nodeid is not FUSE_ROOT_ID.";
    buffer_.response.Reset(0, -ENOENT, buffer_.request.header.unique);
    return;
  }

  if (buffer_.request.header.len == sizeof(FuseRequest)) {
    // Input file name is too large.
    LOG(ERROR) << "Input filename is too large.";
    buffer_.response.Reset(0, -ENOENT, buffer_.request.header.unique);
    return;
  }

  // Ensure that the filename ends with 0.
  const size_t filename_length =
      buffer_.request.header.len - sizeof(fuse_in_header);
  buffer_.request.lookup_name[filename_length] = 0;
  const uint64_t inode =
      static_cast<uint64_t>(atol(buffer_.request.lookup_name));
  if (inode == 0 || inode == LONG_MAX) {
    LOG(ERROR) << "Invalid filename";
    buffer_.response.Reset(0, -ENOENT, buffer_.request.header.unique);
    return;
  }

  const int64_t size = callback->OnGetSize(inode);
  if (size < 0) {
    buffer_.response.Reset(0, size, buffer_.request.header.unique);
    return;
  }

  buffer_.response.Reset(sizeof(fuse_entry_out), 0,
                         buffer_.request.header.unique);
  buffer_.response.entry_out.nodeid = inode;
  buffer_.response.entry_out.attr_valid = 10;
  buffer_.response.entry_out.entry_valid = 10;
  buffer_.response.entry_out.attr.ino = inode;
  buffer_.response.entry_out.attr.mode = S_IFREG | 0777;
  buffer_.response.entry_out.attr.size = size;
}

void FuseAppLoop::HandleGetAttr(FuseAppLoop::Callback* callback) {
  const uint64_t nodeid = buffer_.request.header.nodeid;
  int64_t size;
  uint32_t mode;
  if (nodeid == FUSE_ROOT_ID) {
    size = 0;
    mode = S_IFDIR | 0777;
  } else {
    size = callback->OnGetSize(buffer_.request.header.nodeid);
    if (size < 0) {
      buffer_.response.Reset(0, size, buffer_.request.header.unique);
      return;
    }
    mode = S_IFREG | 0777;
  }

  buffer_.response.Reset(sizeof(fuse_attr_out), 0,
                         buffer_.request.header.unique);
  buffer_.response.attr_out.attr_valid = 10;
  buffer_.response.attr_out.attr.ino = nodeid;
  buffer_.response.attr_out.attr.mode = mode;
  buffer_.response.attr_out.attr.size = size;
}

void FuseAppLoop::HandleOpen(FuseAppLoop::Callback* callback) {
  const int32_t file_handle = callback->OnOpen(buffer_.request.header.nodeid);
  if (file_handle < 0) {
    buffer_.response.Reset(0, file_handle, buffer_.request.header.unique);
    return;
  }
  buffer_.response.Reset(sizeof(fuse_open_out), kFuseSuccess,
                         buffer_.request.header.unique);
  buffer_.response.open_out.fh = file_handle;
}

void FuseAppLoop::HandleFsync(FuseAppLoop::Callback* callback) {
  buffer_.response.Reset(0, callback->OnFsync(buffer_.request.header.nodeid),
                         buffer_.request.header.unique);
}

void FuseAppLoop::HandleRelease(FuseAppLoop::Callback* callback) {
  buffer_.response.Reset(0, callback->OnRelease(buffer_.request.header.nodeid),
                         buffer_.request.header.unique);
}

void FuseAppLoop::HandleRead(FuseAppLoop::Callback* callback) {
  const uint64_t unique = buffer_.request.header.unique;
  const uint64_t nodeid = buffer_.request.header.nodeid;
  const uint64_t offset = buffer_.request.read_in.offset;
  const uint32_t size = buffer_.request.read_in.size;

  if (size > kFuseMaxRead) {
    buffer_.response.Reset(0, -EINVAL, buffer_.request.header.unique);
    return;
  }

  const int32_t read_size = callback->OnRead(nodeid, offset, size,
                                             buffer_.response.read_data);
  if (read_size < 0) {
    buffer_.response.Reset(0, read_size, buffer_.request.header.unique);
    return;
  }

  buffer_.response.ResetHeader(read_size, kFuseSuccess, unique);
}

void FuseAppLoop::HandleWrite(FuseAppLoop::Callback* callback) {
  const uint64_t unique = buffer_.request.header.unique;
  const uint64_t nodeid = buffer_.request.header.nodeid;
  const uint64_t offset = buffer_.request.write_in.offset;
  const uint32_t size = buffer_.request.write_in.size;

  if (size > kFuseMaxWrite) {
    buffer_.response.Reset(0, -EINVAL, buffer_.request.header.unique);
    return;
  }

  const int32_t write_size = callback->OnWrite(nodeid, offset, size,
                                               buffer_.request.write_data);
  if (write_size < 0) {
    buffer_.response.Reset(0, write_size, buffer_.request.header.unique);
    return;
  }

  buffer_.response.Reset(sizeof(fuse_write_out), kFuseSuccess, unique);
  buffer_.response.write_out.size = write_size;
}

bool FuseAppLoop::Start(int raw_fd, FuseAppLoop::Callback* callback) {
  base::unique_fd fd(raw_fd);

  LOG(DEBUG) << "Start fuse loop.";
  while (true) {
    if (!buffer_.request.Read(fd)) {
      return false;
    }

    const uint32_t opcode = buffer_.request.header.opcode;
    LOG(VERBOSE) << "Read a fuse packet, opcode=" << opcode;
    switch (opcode) {
      case FUSE_FORGET:
        // Do not reply to FUSE_FORGET.
        continue;

      case FUSE_LOOKUP:
        HandleLookUp(callback);
        break;

      case FUSE_GETATTR:
        HandleGetAttr(callback);
        break;

      case FUSE_OPEN:
        HandleOpen(callback);
        break;

      case FUSE_READ:
        HandleRead(callback);
        break;

      case FUSE_WRITE:
        HandleWrite(callback);
        break;

      case FUSE_RELEASE:
        HandleRelease(callback);
        break;

      case FUSE_FSYNC:
        HandleFsync(callback);
        break;

      default:
        buffer_.HandleNotImpl();
        break;
    }

    if (!buffer_.response.Write(fd)) {
      LOG(ERROR) << "Failed to write a response to the device.";
      return false;
    }
  }
}

}  // namespace android

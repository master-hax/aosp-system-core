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
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/thread_annotations.h>
#include <android-base/unique_fd.h>

#include "fdemu-internal.h"

using android::base::unique_fd;

namespace fdemu {

// PassthroughFileDescription wraps a system file descriptor and passes through all operations.
struct PassthroughFileDescription : public FileDescription {
  PassthroughFileDescription(FDTable& table, android::base::unique_fd fd)
      : FileDescription(table), fd_(std::move(fd)) {}

  virtual ssize_t read(char* buf, size_t len) override final {
    return ::read(fd_.get(), buf, len);
  }

  virtual ssize_t write(const char* buf, size_t len) override final {
    return ::write(fd_.get(), buf, len);
  }

  virtual ssize_t lseek(off_t offset, int whence) override final {
    return ::lseek(fd_.get(), offset, whence);
  }

  virtual int fstat(struct stat* st) override final {
    struct ::stat real_st;
    int rc = ::fstat(fd_.get(), &real_st);
    if (rc == -1) {
      return -1;
    }
    st->st_mode = real_st.st_mode;
    st->st_size = real_st.st_size;
    return 0;
  }

  virtual FD accept(struct sockaddr* addr, socklen_t* addrlen) override final {
    int result = ::accept(fd_.get(), addr, addrlen);
    if (result == -1) {
      return FD::Invalid();
    }

    // FIXME: Implement me.
    return FD::Invalid();
  }

  virtual FD connect(struct sockaddr* addr, socklen_t addrlen) override final {
    int result = ::connect(fd_.get(), addr, addrlen);
    if (result == -1) {
      return FD::Invalid();
    }

    return FD::Invalid();
  }

  virtual int shutdown(int how) override final {
    return ::shutdown(fd_.get(), how);
  }

  android::base::unique_fd fd_;
};

void FDTable::PreallocateStdio() {
  // Preallocate 0, 1, and 2 for stdin, stdout, stderr.
  for (int fd : {0, 1, 2}) {
    // Avoid duping an FD into a hole that happens to be in STDOUT_FILENO or STDERR_FILENO.
    android::base::unique_fd copy(fcntl(F_DUPFD, 3));

    if (copy == -1) {
      copy.reset(::open("/dev/null", fd == 0 ? O_RDONLY : O_WRONLY));
      CHECK(copy != -1);
    }

    fds_[fd].state = FDEntry::State::kPopulated;
    fds_[fd].value = std::make_shared<PassthroughFileDescription>(*this, std::move(copy));
  }
}

FD open(FDTable& table, const char* path, int flags, ...) {
  FDReservation reservation = FDTable::Global.Allocate();
  if (!reservation) {
    // errno has already been set for us.
    return FD::Invalid();
  }

  // Always extract the mode, even if it's not actually there.
  va_list ap;
  va_start(ap, flags);
  int mode = va_arg(ap, int);

  unique_fd fd(::open(path, flags, mode));
  if (fd == -1) {
    return FD::Invalid();
  }
  return reservation.Populate(std::make_shared<PassthroughFileDescription>(table, std::move(fd)));
}

}  // namespace fdemu

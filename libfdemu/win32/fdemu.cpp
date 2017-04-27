#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

// Winsock headers must be included before <windows.h>.
#include <ws2tcpip.h>

#include <windows.h>

#include <limits>
#include <memory>
#include <mutex>
#include <vector>

#include <android-base/errors.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/utf8.h>

#include "fdemu-internal.h"
#include "fdemu.h"

namespace fdemu {

struct UniqueHandle {
  UniqueHandle() : handle_(INVALID_HANDLE_VALUE) {}
  explicit UniqueHandle(HANDLE handle) : handle_(handle) {}
  ~UniqueHandle() {
    if (valid()) {
      CloseHandle(handle_);
    }
  }

  bool valid() { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }

  HANDLE get() { return handle_; }

  HANDLE release() {
    HANDLE result = handle_;
    handle_ = INVALID_HANDLE_VALUE;
    return result;
  }

  HANDLE handle_;
};

struct HandleFileDescription : public FileDescription {
  HandleFileDescription(FDTable& table, HANDLE handle) : FileDescription(table), handle_(handle) {}

  virtual ssize_t read(char* buf, size_t len) override {
    DWORD read_bytes;
    if (len > std::numeric_limits<DWORD>::max()) {
      errno = EOVERFLOW;
      return -1;
    }

    if (!ReadFile(handle_.get(), buf, static_cast<DWORD>(len), &read_bytes, nullptr)) {
      // TODO: GetLastError?
      errno = EIO;
      return -1;
    }

    return read_bytes;
  }

  virtual ssize_t write(const char* buf, size_t len) override {
    DWORD wrote_bytes;
    if (len > std::numeric_limits<DWORD>::max()) {
      errno = EOVERFLOW;
      return -1;
    }

    if (!WriteFile(handle_.get(), buf, static_cast<DWORD>(len), &wrote_bytes, nullptr)) {
      // TODO: GetLastError?
      errno = EIO;
      return -1;
    }

    return wrote_bytes;
  }

  virtual ssize_t lseek(off_t offset, int whence) override {
    DWORD method;
    switch (whence) {
      case SEEK_SET:
        method = FILE_BEGIN;
        break;
      case SEEK_CUR:
        method = FILE_CURRENT;
        break;
      case SEEK_END:
        method = FILE_END;
        break;
      default:
        errno = EINVAL;
        return -1;
    }

    // TODO: Broken when seeking past the beginning of a file?
    // TODO: Use SetFilePointerEx?
    if (offset > std::numeric_limits<DWORD>::max()) {
      errno = EOVERFLOW;
      return -1;
    }
    DWORD result = SetFilePointer(handle_.get(), offset, nullptr, method);
    if (result == INVALID_SET_FILE_POINTER) {
      // TODO: GetLastError?
      errno = EIO;
      return -1;
    }

    return result;
  }

  virtual int fstat(struct stat* st) override {
    UNUSED(st);
    abort();
  }

  virtual FD accept(struct sockaddr* addr, socklen_t* addrlen) override {
    UNUSED(addr, addrlen);
    errno = ENOTSOCK;
    return FD::Invalid();
  }

  virtual FD connect(struct sockaddr* addr, socklen_t addrlen) override {
    UNUSED(addr, addrlen);
    errno = ENOTSOCK;
    return FD::Invalid();
  }

  virtual int shutdown(int how) override {
    UNUSED(how);
    errno = ENOTSOCK;
    return -1;
  }

  UniqueHandle handle_;
};

void FDTable::PreallocateStdio() {
  // FIXME: Implement me.
}

FD open(FDTable& table, const char* path, int flags, ...) {
  // Reserve an FD before we do anything, in case we're out.
  FDReservation reservation = FDTable::Global.Allocate();
  if (!reservation) {
    // errno has already been set for us.
    return FD::Invalid();
  }

  DWORD desired_access = 0;
  DWORD share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;

  int access_flags = flags & (O_RDWR | O_RDONLY | O_WRONLY);
  if (access_flags == O_RDWR) {
    desired_access = GENERIC_READ | GENERIC_WRITE;
  } else if (access_flags == O_RDONLY) {
    desired_access = GENERIC_READ;
  } else if (access_flags == O_WRONLY) {
    desired_access = GENERIC_WRITE;
  } else {
    errno = EINVAL;
    return FD::Invalid();
  }

  std::wstring path_wide;
  if (!android::base::UTF8ToWide(path, &path_wide)) {
    // TODO: errno?
    return FD::Invalid();
  }

  // FIXME: Actually handle O_CREAT, O_EXCL, etc.
  UniqueHandle handle(CreateFileW(path_wide.c_str(), desired_access, share_mode, nullptr,
                                  OPEN_EXISTING, 0, nullptr));

  if (!handle.valid()) {
    // FIXME: errno?
    return FD::Invalid();
  }

  return reservation.Populate(std::make_shared<HandleFileDescription>(table, handle.release()));
}

}  // namespace fdemu

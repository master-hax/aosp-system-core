#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>

#include <string>

#include "android-base/logging.h"
#include "log/log.h"
#include "ziparchive/zip_archive.h"

#ifdef _ANDROID_
#include <selinux/label.h>
#include <selinux/selinux.h>
#endif

#if !defined(_WIN32)
static bool IsDir(const std::string& dirpath) {
  struct stat st;
  if (stat(dirpath.c_str(), &st) == 0) {
    if (S_ISDIR(st.st_mode)) {
      return true;
    }
  }
  return false;
}

bool MKdirWithParents(const std::string& path, int mode, const struct utimbuf *timestamp,
                             __attribute__((unused)) void* sehnd) {
  size_t prev_end = 0;
  while (prev_end < path.size()) {
    size_t next_end = path.find('/', prev_end + 1);
    if (next_end == std::string::npos) {
      break;
    }
    std::string dir_path = path.substr(0, next_end);
    if (!IsDir(dir_path)) {

#ifdef _ANDROID_
      char *secontext = nullptr;
      if (sehnd) {
        selabel_lookup(reinterpret_cast<selabel_handle>(sehnd), &secontext, dir_path.c_str(), mode);
        setfscreatecon(secontext);
      }
#endif
      int ret = mkdir(dir_path.c_str(), mode);
#ifdef _ANDROID_
      if (secontext) {
        freecon(secontext);
        setfscreatecon(NULL);
      }
#endif
      if (ret != 0) {
        ALOGE("failed to create dir %s, error: %s", dir_path.c_str(), strerror(errno));
        return false;
      }

      if (timestamp != NULL && utime(dir_path.c_str(), timestamp)) {
        return -1;
      }
    }
    prev_end = next_end;
  }
  return true;
}

bool RemoveDir(const std::string& path) {
  if (!IsDir(path)) {
    if (unlink(path.c_str()) != 0) {
      ALOGE("unlink %s failed: %s", path.c_str(), strerror(errno));
      return false;
    }
    return true;
  }

  DIR* dir = opendir(path.c_str());
  if (dir == nullptr) {
    return false;
  }

  struct dirent *de;
  bool fail = false;
  errno = 0;
  while ((de = readdir(dir)) != NULL) {
    if (!strcmp(de->d_name, "..") || !strcmp(de->d_name, ".")) {
      continue;
    }
    std::string dn = path + std::string(de->d_name);
    if (!RemoveDir(dn)) {
      fail = true;
      break;
    }
    errno = 0;
  }
  /* in case readdir or unlink_recursive failed */
  if (fail || errno < 0) {
    ALOGE("failed to remove %s: %s", path.c_str(), strerror(errno));
    if (closedir(dir) != 0) {
      ALOGE("failed to close dir: %s", strerror(errno));
    }
    return false;
  }
  if (rmdir(path.c_str()) != 0) {
    ALOGE("failed to remove %s: %s", path.c_str(), strerror(errno));
    return false;
  }
  return true;
}
#endif

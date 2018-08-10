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

#define LOG_TAG "apexd"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include <dirent.h>
#include <linux/loop.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

// TODO: stop using vold's Loop.
#include "../../vold/Loop.h"
// TODO: stop using vold's Ext4.
#include "../../vold/fs/Ext4.h"
#include "apexd.h"

using android::base::Basename;
using android::base::EndsWith;
using android::base::StringPrintf;
using std::string;

namespace android {
namespace apex {

void installPackage(const string& full_path) {
  LOG(INFO) << "Installing " << full_path;

  // TODO: open file and read manifest. For now we simply parse the basename
  // looking for an identifier which we'll use as mount point.
  // We also assume that the .apex file is a mountable image.
  string packageId = Basename(full_path.substr(0, full_path.length() - 5));
  string mountPoint = StringPrintf("%s/%s", APEX_ROOT, packageId.c_str());

  string loopback;

  // TODO: stop using vold's Loop.
  int ret = Loop::create(full_path, loopback);
  if (ret != 0) {
    PLOG(ERROR) << "Can't create loopback device for " << full_path;
    return;
  }

  LOG(INFO) << "Loopback device created: " << loopback;
  LOG(INFO) << "Creating mount point: " << mountPoint;
  mkdir(mountPoint.c_str(), 0755);

  // TODO: stop using vold's Ext4.
  status_t status =
      android::vold::ext4::Mount(loopback, mountPoint.c_str(), true /* ro */,
                                 false /* remount */, true /* executable */);
  if (status == android::OK) {
    LOG(INFO) << "Successfully mounted on " << mountPoint;
  } else {
    PLOG(ERROR) << "Mounting failed " << status;
  }
}

void unmountAndDetachExistingImages() {
  LOG(INFO) << "Scanning " << APEX_ROOT
            << " looking for packages already mounted.";
  auto d = std::unique_ptr<DIR, int (*)(DIR*)>(opendir(APEX_ROOT), closedir);
  if (!d) {
    // Nothing to do
    return;
  }

  struct dirent* dp;
  while ((dp = readdir(d.get())) != NULL) {
    if (dp->d_type != DT_DIR) {
      continue;
    }
    // Lazily try to umount whatever is mounted.
    if (umount2(StringPrintf("%s/%s", APEX_ROOT, dp->d_name).c_str(),
                UMOUNT_NOFOLLOW | MNT_DETACH) != 0 &&
        errno != EINVAL && errno != ENOENT) {
      PLOG(ERROR) << "Failed to unmount directory " << APEX_ROOT << "/"
                  << dp->d_name;
    }
  }

  // TODO: stop using vold's Loop.
  Loop::destroyAll();
}

void setupApexRoot() {
  LOG(INFO) << "Creating APEX mount point at " << APEX_ROOT;
  mkdir(APEX_ROOT, 0755);
}

void scanPackagesDirAndMount() {
  LOG(INFO) << "Scanning " << APEX_PACKAGES_DIR
            << " looking for APEX packages.";
  auto d =
      std::unique_ptr<DIR, int (*)(DIR*)>(opendir(APEX_PACKAGES_DIR), closedir);

  if (!d) {
    LOG(WARNING) << "Package directory " << APEX_PACKAGES_DIR
                 << " not found, nothing to do.";
    return;
  }
  struct dirent* dp;
  while ((dp = readdir(d.get())) != NULL) {
    if (dp->d_type != DT_REG || !EndsWith(dp->d_name, ".apex")) {
      continue;
    }
    LOG(INFO) << "Found " << dp->d_name;

    installPackage(StringPrintf("%s/%s", APEX_PACKAGES_DIR, dp->d_name));
  }
}
}  // namespace apex
}  // namespace android

int main(int /*argc*/, char** /*argv*/) {
  android::apex::unmountAndDetachExistingImages();
  android::apex::setupApexRoot();
  android::apex::scanPackagesDirAndMount();
  // TODO: start accepting IPC commands and become a daemon.
  return 0;
}

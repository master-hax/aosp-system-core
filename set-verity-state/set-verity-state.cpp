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

#include <libavb_user/libavb_user.h>
#include <stdio.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <fs_mgr_overlayfs.h>

#ifdef ALLOW_DISABLE_VERITY
static const bool kAllowDisableVerity = true;
#else
static const bool kAllowDisableVerity = false;
#endif

/* Helper function to get A/B suffix, if any. If the device isn't
 * using A/B the empty string is returned. Otherwise either "_a",
 * "_b", ... is returned.
 */
static std::string get_ab_suffix() {
  return android::base::GetProperty("ro.boot.slot_suffix", "");
}

static bool is_avb_device_locked() {
  return android::base::GetProperty("ro.boot.vbmeta.device_state", "") == "locked";
}

static bool is_using_avb() {
  // Figure out if we're using VB1.0 or VB2.0 (aka AVB) - by
  // contract, androidboot.vbmeta.digest is set by the bootloader
  // when using AVB).
  return !android::base::GetProperty("ro.boot.vbmeta.digest", "").empty();
}

static bool overlayfs_setup(bool enable) {
  auto change = false;
  errno = 0;
  if (enable ? fs_mgr_overlayfs_teardown(nullptr, &change)
             : fs_mgr_overlayfs_setup(nullptr, nullptr, &change)) {
    if (change) {
      printf("%s overlayfs\n", enable ? "disabling" : "using");
    }
  } else if (errno) {
    PLOG(ERROR) << "Failed to " << (enable ? "teardown" : "setup") << " overlayfs";
  }
  return change;
}

/* Use AVB to turn verity on/off */
static bool set_avb_verity_enabled_state(AvbOps* ops, bool enable_verity) {
  std::string ab_suffix = get_ab_suffix();
  bool verity_enabled;

  if (is_avb_device_locked()) {
    LOG(ERROR) << "Device is locked. Please unlock the device first";
    return false;
  }

  if (!avb_user_verity_get(ops, ab_suffix.c_str(), &verity_enabled)) {
    LOG(ERROR) << "Error getting verity state";
    return false;
  }

  if ((verity_enabled && enable_verity) || (!verity_enabled && !enable_verity)) {
    printf("verity is already %s\n", verity_enabled ? "enabled" : "disabled");
    return false;
  }

  if (!avb_user_verity_set(ops, ab_suffix.c_str(), enable_verity)) {
    LOG(ERROR) << "Error setting verity state";
    return false;
  }

  printf("Successfully %s verity\n", enable_verity ? "enabled" : "disabled");
  return true;
}

int main(int argc, char* argv[]) {
  android::base::InitLogging(argv, android::base::StderrLogger);

  if (!kAllowDisableVerity || !android::base::GetBoolProperty("ro.debuggable", false)) {
    errno = EPERM;
    PLOG(ERROR) << "Cannot disable/enable verity on user build";
    return 1;
  }

  if (getuid() != 0) {
    errno = EACCES;
    PLOG(ERROR) << "Must be running as root";
    return 1;
  }

  if (!is_using_avb()) {
    LOG(ERROR) << "VB1.0 is no longer supported";
    return 1;
  }

  if (argc == 0) {
    LOG(FATAL) << "set-verity-state called with empty argv";
  }

  std::optional<bool> enable_opt;
  std::string procname = android::base::Basename(argv[0]);
  if (procname == "enable-verity") {
    enable_opt = true;
  } else if (procname == "disable-verity") {
    enable_opt = false;
  }

  if (!enable_opt.has_value()) {
    if (argc != 2) {
      printf("usage: %s [1|0]\n", argv[0]);
      return 1;
    }

    if (strcmp(argv[1], "1") == 0) {
      enable_opt = true;
    } else if (strcmp(argv[1], "0") == 0) {
      enable_opt = false;
    } else {
      printf("usage: %s [1|0]\n", argv[0]);
      return 1;
    }
  }

  bool enable = enable_opt.value();

  std::unique_ptr<AvbOps, decltype(&avb_ops_user_free)> ops(avb_ops_user_new(), &avb_ops_user_free);
  if (!ops) {
    LOG(ERROR) << "Error getting AVB ops";
    return 1;
  }

  bool any_changed = false;
  any_changed |= set_avb_verity_enabled_state(ops.get(), enable);
  any_changed |= overlayfs_setup(enable);

  if (any_changed) {
    printf("Now reboot your device for settings to take effect\n");
  }

  return 0;
}

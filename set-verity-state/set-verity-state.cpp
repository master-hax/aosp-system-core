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

#include <errno.h>
#include <libavb_user/libavb_user.h>
#include <stdio.h>

#include <iostream>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <fs_mgr_overlayfs.h>
#include <log/log_properties.h>

using namespace std::string_literals;

#ifdef ALLOW_DISABLE_VERITY
static const bool kAllowDisableVerity = true;
#else
static const bool kAllowDisableVerity = false;
#endif

static void suggest_run_adb_root() {
  if (getuid() != 0) printf("Maybe run adb root?\n");
}

// Enable here refers to verity state, not overlayfs.
static bool SetupOrTeardownOverlayfs(bool enable, const char* mount_point, bool* change) {
  if (!enable) {
    if (!fs_mgr_overlayfs_setup(mount_point, change)) {
      std::cout << "Overlayfs setup";
      if (mount_point) {
        std::cout << " for " << mount_point;
      }
      std::cout << " failed\n";
      return false;
    }
  } else {
    auto rv = fs_mgr_overlayfs_teardown(mount_point, change);
    if (rv == OverlayfsTeardownResult::Error) {
      std::cout << "Overlayfs teardown";
      if (mount_point) {
        std::cout << " for " << mount_point;
      }
      std::cout << " failed\n";
      return false;
    }
    if (rv == OverlayfsTeardownResult::Busy) {
      std::cout << "Overlayfs is still active; please reboot to disable.\n";
      return true;
    }
  }
  if (*change) {
    std::cout << (enable ? "disabling" : "enabling") << " overlayfs";
    if (mount_point) {
      std::cout << " for " << mount_point;
    }
    std::cout << "\n";
  }
  return true;
}

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

/* Use AVB to turn verity on/off */
static bool set_avb_verity_enabled_state(AvbOps* ops, bool enable_verity) {
  std::string ab_suffix = get_ab_suffix();
  bool verity_enabled;

  if (is_avb_device_locked()) {
    printf("Device is locked. Please unlock the device first\n");
    return false;
  }

  if (!avb_user_verity_get(ops, ab_suffix.c_str(), &verity_enabled)) {
    printf("Error getting verity state. Try adb root first?\n");
    return false;
  }

  if ((verity_enabled && enable_verity) || (!verity_enabled && !enable_verity)) {
    printf("verity is already %s\n", verity_enabled ? "enabled" : "disabled");
    return false;
  }

  if (!avb_user_verity_set(ops, ab_suffix.c_str(), enable_verity)) {
    printf("Error setting verity\n");
    return false;
  }

  printf("Successfully %s verity\n", enable_verity ? "enabled" : "disabled");
  return true;
}

int main(int argc, char* argv[]) {
  if (argc == 0) {
    LOG(FATAL) << "set-verity-state called with empty argv";
  }

  bool enable = false;
  std::string procname = android::base::Basename(argv[0]);
  if (procname == "enable-verity") {
    enable = true;
  } else if (procname == "disable-verity") {
    enable = false;
  } else if (argc == 2 && (argv[1] == "1"s || argv[1] == "0"s)) {
    enable = (argv[1] == "1"s);
  } else {
    printf("usage: %s [1|0]\n", argv[0]);
    return 1;
  }

  bool verity_changed = false;

  // Figure out if we're using VB1.0 or VB2.0 (aka AVB) - by
  // contract, androidboot.vbmeta.digest is set by the bootloader
  // when using AVB).
  bool using_avb = !android::base::GetProperty("ro.boot.vbmeta.digest", "").empty();

  // If using AVB, dm-verity is used on any build so we want it to
  // be possible to disable/enable on any build (except USER). For
  // VB1.0 dm-verity is only enabled on certain builds.
  if (!using_avb) {
    if (!kAllowDisableVerity) {
      printf("%s only works for userdebug builds\n", argv[0]);
    }

    if (!android::base::GetBoolProperty("ro.secure", false)) {
      bool change;
      SetupOrTeardownOverlayfs(enable, nullptr, &change);
      printf("verity not enabled - ENG build\n");
      return 0;
    }
  }

  // Should never be possible to disable dm-verity on a USER build
  // regardless of using AVB or VB1.0.
  if (!__android_log_is_debuggable()) {
    printf("verity cannot be disabled/enabled - USER build\n");
    return 0;
  }

  bool any_changed = false;
  if (using_avb) {
    // Yep, the system is using AVB.
    AvbOps* ops = avb_ops_user_new();
    if (ops == nullptr) {
      printf("Error getting AVB ops\n");
      return 1;
    }
    if (set_avb_verity_enabled_state(ops, enable)) {
      verity_changed = true;
    }
    avb_ops_user_free(ops);
  }

  bool overlayfs_changed = false;
  if (!SetupOrTeardownOverlayfs(enable, nullptr, &overlayfs_changed)) {
    suggest_run_adb_root();
  }

  if (verity_changed || overlayfs_changed) {
    printf("Now reboot your device for settings to take effect\n");
  }

  return 0;
}

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

package com.android.tests.vendoroverlay;

import com.android.tradefed.device.DeviceNotAvailableException;
import com.android.tradefed.log.LogUtil.CLog;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.CommandResult;
import com.android.tradefed.util.CommandStatus;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Test the vendor overlay feature. This test disables dm-verity.
 */
@RunWith(DeviceJUnit4ClassRunner.class)
public class VendorOverlayHostTest extends BaseHostJUnit4Test {
  @Before
  public void setup() throws DeviceNotAvailableException {
    Assume.assumeTrue("Test requires root", getDevice().enableAdbRoot());
  }

  private boolean cmdSucceeded(CommandResult result) {
    return result.getStatus() == CommandStatus.SUCCESS;
  }

  private void assumeCmdSuccess(String msg, CommandResult res) throws DeviceNotAvailableException {
    try {
      Assume.assumeTrue(msg, cmdSucceeded(res));
    } finally {
      tearDown();
    }
  }

  /**
   * Tests that files in the appropriate /product/vendor_overlay dir are overlaid onto /vendor.
   */
  @Test
  public void testVendorOverlay() throws DeviceNotAvailableException {
    // Skip test if kernel lacks required OverlayFS support
    Assume.assumeTrue("Skipping vendor overlay test due to lack of necessary OverlayFS support",
        testConditionsMet());

    getDevice().remountSystemWritable();

    // Create files and modify policy
    CommandResult result = getDevice().executeShellV2Command(
        "cp /system/etc/selinux/plat_file_contexts /system/etc/selinux/plat_file_contexts.bak");
    assumeCmdSuccess("Couldn't backup plat_file_contexts", result);
    result = getDevice().executeShellV2Command(
        "echo '/(product|system/product)/vendor_overlay/[A-Z]/.* u:object_r:vendor_file:s0'" +
        " >> /system/etc/selinux/plat_file_contexts");
    assumeCmdSuccess("Couldn't modify plat_file_contexts", result);
    result = getDevice().executeShellV2Command("mkdir -p /vendor/testdir");
    assumeCmdSuccess("Couldn't create /vendor/testdir", result);
    result = getDevice().executeShellV2Command("mkdir -p /vendor/diffcontext");
    assumeCmdSuccess("Couldn't create /vendor/diffcontext", result);
    result = getDevice().executeShellV2Command(
        "mkdir -p \"/product/vendor_overlay/$(getprop ro.vndk.version)/testdir\"");
    assumeCmdSuccess("Couldn't create testdir on vendor_overlay", result);
    result = getDevice().executeShellV2Command(
        "echo \"overlay\" > \"/product/vendor_overlay/$(getprop ro.vndk.version)/testdir/test\"");
    assumeCmdSuccess("Couldn't create text file in testdir", result);
    result = getDevice().executeShellV2Command(
        "mkdir -p \"/product/vendor_overlay/$(getprop ro.vndk.version)/noexist/test\"");
    assumeCmdSuccess("Couldn't create test dir in noexist", result);
    result = getDevice().executeShellV2Command(
        "mkdir -p \"/product/vendor_overlay/$(getprop ro.vndk.version)/diffcontext/test\"");
    assumeCmdSuccess("Couldn't create test dir in diffcontext", result);
    result = getDevice().executeShellV2Command(
        "restorecon -r \"/product/vendor_overlay/$(getprop ro.vndk.version)/testdir\"");
    assumeCmdSuccess("Couldn't write testdir context", result);

    getDevice().reboot();

    // Test that the file was overlaid properly
    result = getDevice().executeShellV2Command("[ $(cat /vendor/testdir/test) = overlay ]");
    Assert.assertTrue("test file was not overlaid onto /vendor/", cmdSucceeded(result));
    result = getDevice().executeShellV2Command("[ ! -d /vendor/noexist/test ]");
    Assert.assertTrue("noexist dir shouldn't exist on /vendor", cmdSucceeded(result));
    result = getDevice().executeShellV2Command("[ ! -d /vendor/diffcontext/test ]");
    Assert.assertTrue("diffcontext dir shouldn't exist on /vendor", cmdSucceeded(result));
  }

  // Duplicate of fs_mgr_overlayfs_valid() logic
  public boolean testConditionsMet() throws DeviceNotAvailableException {
    if (cmdSucceeded(getDevice().executeShellV2Command(
        "[ -e /sys/module/overlay/parameters/override_creds ]"))) {
      return true;
    }
    if (cmdSucceeded(getDevice().executeShellV2Command("[ ! -e /sys/module/overlay ]"))) {
      return false;
    }
    // Major kernel version number < 4
    if (cmdSucceeded(getDevice().executeShellV2Command(
        "[ $(cat /proc/version | cut -d ' ' -f 3 | cut -d '.' -f 1) -lt 4 ]"))) {
      return true;
    }
    // Major kernel version number > 4
    if (cmdSucceeded(getDevice().executeShellV2Command(
        "[ $(cat /proc/version | cut -d ' ' -f 3 | cut -d '.' -f 1) -gt 4 ]"))) {
      return false;
    }
    // Minor kernel version number > 6
    if (cmdSucceeded(getDevice().executeShellV2Command(
        "[ $(cat /proc/version | cut -d ' ' -f 3 | cut -d '.' -f 2) -gt 6 ]"))) {
      return false;
    }
    return true;
  }

  private void tearDown() throws DeviceNotAvailableException {
    // Undo file modifications
    CommandResult result = getDevice().executeShellV2Command(
        "mv /system/etc/selinux/plat_file_contexts.bak /system/etc/selinux/plat_file_contexts");
    result = getDevice().executeShellV2Command(
        "rm -rf /vendor/testdir /vendor/diffcontext" +
        " \"/product/vendor_overlay/$(getprop ro.vndk.version)/testdir\"" +
        " \"/product/vendor_overlay/$(getprop ro.vndk.version)/diffcontext\"" +
        " \"/product/vendor_overlay/$(getprop ro.vndk.version)/noexist\"");
    getDevice().reboot();
  }
}


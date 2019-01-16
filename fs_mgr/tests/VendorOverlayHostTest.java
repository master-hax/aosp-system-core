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

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;

/**
 * Test the vendor overlay feature
 */
@RunWith(DeviceJUnit4ClassRunner.class)
public class VendorOverlayHostTest extends BaseHostJUnit4Test {
    /**
     * Tests that files in the appropriate /product/vendor_overlay directory are overlaid onto /vendor.
     */
    @Test
    public void testVendorOverlay()
                                throws DeviceNotAvailableException, IOException {
        Assert.assertTrue("Couldn't get root", getDevice().enableAdbRoot());

        // Skip test if kernel lacks required OverlayFS support
        if (!testConditionsMet()) {
            CLog.i("Skipping vendor overlay test due to lack of necessary OverlayFS support");
            getDevice().disableAdbRoot();
            return;
        }

        getDevice().remountSystemWritable();

        // Create files and modify policy
        CommandResult result = getDevice().executeShellV2Command("echo '/(product|system/product)/vendor_overlay/[A-Z]/.* u:object_r:vendor_file:s0' >> /system/etc/selinux/plat_file_contexts");
        Assert.assertEquals("Couldn't modify plat_file_contexts", CommandStatus.SUCCESS, result.getStatus());
        result = getDevice().executeShellV2Command("mkdir -p /vendor/testdir");
        Assert.assertEquals("Couldn't create /vendor/testdir", CommandStatus.SUCCESS, result.getStatus());
        result = getDevice().executeShellV2Command("mkdir -p /vendor/diffcontext");
        Assert.assertEquals("Couldn't create /vendor/diffcontext", CommandStatus.SUCCESS, result.getStatus());
        result = getDevice().executeShellV2Command("mkdir -p \"/product/vendor_overlay/$(getprop ro.vndk.version)/testdir\"");
        Assert.assertEquals("Couldn't create testdir on vendor_overlay", CommandStatus.SUCCESS, result.getStatus());
        result = getDevice().executeShellV2Command("echo \"overlay\" > \"/product/vendor_overlay/$(getprop ro.vndk.version)/testdir/test\"");
        Assert.assertEquals("Couldn't create text file in testdir", CommandStatus.SUCCESS, result.getStatus());
        result = getDevice().executeShellV2Command("mkdir -p \"/product/vendor_overlay/$(getprop ro.vndk.version)/noexist/test\"");
        Assert.assertEquals("Couldn't create test dir in noexist", CommandStatus.SUCCESS, result.getStatus());
        result = getDevice().executeShellV2Command("mkdir -p \"/product/vendor_overlay/$(getprop ro.vndk.version)/diffcontext/test\"");
        Assert.assertEquals("Couldn't create test dir in diffcontext", CommandStatus.SUCCESS, result.getStatus());
        result = getDevice().executeShellV2Command("restorecon -r \"/product/vendor_overlay/$(getprop ro.vndk.version)/testdir\"");
        Assert.assertEquals("Couldn't write testdir context", CommandStatus.SUCCESS, result.getStatus());

        getDevice().nonBlockingReboot();
        getDevice().waitForDeviceAvailable();
        getDevice().enableAdbRoot();

        // Test that the file was overlaid properly
        result = getDevice().executeShellV2Command("[ $(cat /vendor/testdir/test) = overlay ]");
        Assert.assertEquals("test file was not overlaid onto /vendor/", CommandStatus.SUCCESS, result.getStatus());
        result = getDevice().executeShellV2Command("[ ! -d /vendor/noexist/test ]");
        Assert.assertEquals("noexist dir shouldn't exist on /vendor", CommandStatus.SUCCESS, result.getStatus());
        result = getDevice().executeShellV2Command("[ ! -d /vendor/diffcontext/test ]");
        Assert.assertEquals("diffcontext dir shouldn't exist on /vendor", CommandStatus.SUCCESS, result.getStatus());

        getDevice().enableAdbRoot();
        getDevice().executeAdbCommand("enable-verity");
        getDevice().nonBlockingReboot();
        getDevice().waitForDeviceAvailable();
    }


    // Duplicate of fs_mgr_overlayfs_valid() logic
    // Requires root permissions
    private boolean testConditionsMet()
                                throws DeviceNotAvailableException {
        if (getDevice().executeShellV2Command("[ -e /sys/module/overlay/parameters/override_creds ]").getStatus() == CommandStatus.SUCCESS)
            return true;
        if (getDevice().executeShellV2Command("[ ! -e /sys/module/overlay ]").getStatus() == CommandStatus.SUCCESS)
            return false;
        // Major kernel version number < 4
        if (getDevice().executeShellV2Command("[ $(cat /proc/version | cut -d ' ' -f 3 | cut -d '.' -f 1) -lt 4 ]").getStatus() == CommandStatus.SUCCESS)
            return true;
        // Major kernel version number > 4
        if (getDevice().executeShellV2Command("[ $(cat /proc/version | cut -d ' ' -f 3 | cut -d '.' -f 1) -gt 4 ]").getStatus() == CommandStatus.SUCCESS)
            return false;
        // Minor kernel version number > 6
        if (getDevice().executeShellV2Command("[ $(cat /proc/version | cut -d ' ' -f 3 | cut -d '.' -f 2) -gt 6 ]").getStatus() == CommandStatus.SUCCESS)
            return false;
        return true;
    }
}


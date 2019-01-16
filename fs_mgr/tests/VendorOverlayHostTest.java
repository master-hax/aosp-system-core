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
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.CommandResult;
import com.android.tradefed.util.CommandStatus;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;

/**
 * Test the vendor overlay feature (go/vendor-overlay-1p)
 */
@RunWith(DeviceJUnit4ClassRunner.class)
public class VendorOverlayHostTest extends BaseHostJUnit4Test {
    /**
     * Tests that files in the appropriate /product/vendor_overlay directory are overlaid onto /vendor.
     */
    @Test
    public void testVendorOverlay()
                                throws DeviceNotAvailableException, IOException {
        // Skip test if kernel lacks OverlayFS support
        CommandResult result = getDevice().executeShellV2Command("[ -d /sys/module/overlay ]");
        if (result.getStatus() != CommandStatus.SUCCESS)
            return;

        Assert.assertTrue(getDevice().enableAdbRoot());
        getDevice().remountSystemWritable();

        // Create files and modify policy
        result = getDevice().executeShellV2Command("echo '/(product|system/product)/vendor_overlay/[A-Z]/.* u:object_r:vendor_file:s0' >> /system/etc/selinux/plat_file_contexts");
        Assert.assertEquals(CommandStatus.SUCCESS, result.getStatus());
        result = getDevice().executeShellV2Command("mkdir -p /vendor/testdir");
        Assert.assertEquals(CommandStatus.SUCCESS, result.getStatus());
        result = getDevice().executeShellV2Command("mkdir -p \"/product/vendor_overlay/$(getprop ro.vndk.version)/testdir/test\"");
        Assert.assertEquals(CommandStatus.SUCCESS, result.getStatus());
        result = getDevice().executeShellV2Command("restorecon -r \"/product/vendor_overlay/$(getprop ro.vndk.version)\"");
        Assert.assertEquals(CommandStatus.SUCCESS, result.getStatus());

        getDevice().nonBlockingReboot();
        getDevice().waitForDeviceAvailable();

        // Test that the file was overlaid properly
        result = getDevice().executeShellV2Command("[ -d /vendor/testdir/test ]");
        Assert.assertEquals(CommandStatus.SUCCESS, result.getStatus());

        getDevice().enableAdbRoot();
        getDevice().executeAdbCommand("enable-verity");
        getDevice().nonBlockingReboot();
        getDevice().waitForDeviceAvailable();
    }
}


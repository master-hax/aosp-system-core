/*
 * Copyright (C) 2022 The Android Open Source Project
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

package com.android.tests.init;

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assume.assumeTrue;

import com.android.server.os.TombstoneProtos.Tombstone;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.CommandResult;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;

@RunWith(DeviceJUnit4ClassRunner.class)
public class MteUpgradeTest extends BaseHostJUnit4Test {
    String mUUID;

    @Before
    public void setUp() throws Exception {
        CommandResult result =
                getDevice().executeShellV2Command("/system/bin/mte_crash --checking");
        assumeTrue("mte_crash needs to segfault", result.getExitCode() == 139);
        // getDevice().reboot();
        mUUID = java.util.UUID.randomUUID().toString();
        assertThat(getDevice().setProperty("sys.mte_crash_test_uuid", mUUID)).isTrue();
    }

    @After
    public void tearDown() throws Exception {
        getDevice().executeShellV2Command("stop mte_crash");
        getDevice().executeShellV2Command("stop mte_crash_downgrade");
        getDevice().setProperty("sys.mte_crash_test_uuid", "");
    }

    Tombstone parseTombstone(String tombstonePath) throws Exception {
        File tombstoneFile = getDevice().pullFile(tombstonePath);
        InputStream istr = new FileInputStream(tombstoneFile);
        Tombstone tombstoneProto;
        try {
            tombstoneProto = Tombstone.parseFrom(istr);
        } finally {
            istr.close();
        }
        return tombstoneProto;
    }

    @Test
    public void testCrash() throws Exception {
        CommandResult result = getDevice().executeShellV2Command("start mte_crash");
        assertThat(result.getExitCode()).isEqualTo(0);
        java.lang.Thread.sleep(20000);
        String[] tombstonesAfter = getDevice().getChildren("/data/tombstones");
        ArrayList<String> segvCodeNames = new ArrayList<String>();
        for (String tombstone : tombstonesAfter) {
            if (!tombstone.endsWith(".pb")) {
                continue;
            }
            String tombstoneFilename = "/data/tombstones/" + tombstone;
            Tombstone tombstoneProto = parseTombstone(tombstoneFilename);
            if (!tombstoneProto.getCommandLineList().stream()
                    .anyMatch(x -> x.contains("mte_crash"))) {
                continue;
            }
            if (!tombstoneProto.getCommandLineList().stream().anyMatch(x -> x.contains(mUUID))) {
                continue;
            }
            assertThat(tombstoneProto.getSignalInfo().getName()).isEqualTo("SIGSEGV");
            segvCodeNames.add(tombstoneProto.getSignalInfo().getCodeName());
            getDevice().deleteFile(tombstoneFilename);
            // remove the non .pb file as well.
            getDevice().deleteFile(tombstoneFilename.substring(0, tombstoneFilename.length() - 3));
        }
        assertThat(segvCodeNames.size()).isAtLeast(3);
        assertThat(segvCodeNames.get(0)).isEqualTo("SEGV_MTEAERR");
        assertThat(segvCodeNames.get(1)).isEqualTo("SEGV_MTESERR");
        assertThat(segvCodeNames.get(2)).isEqualTo("SEGV_MTEAERR");
    }

    @Test
    public void testDowngrade() throws Exception {
        CommandResult result =
                getDevice()
                        .executeShellV2Command(
                                "MEMTAG_OPTIONS=async TIMED_UPGRADE_MTE_TO_SYNC=1"
                                        + " /system/bin/mte_crash --check-downgrade");
        assertThat(result.getExitCode()).isEqualTo(0);
    }
}

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

#include <string>

#include <android-base/strings.h>
#include <gtest/gtest.h>

#include "../fs_mgr_priv_boot_config.h"

using namespace std::literals;

namespace {

const std::string cmdline =
        "rcupdate.rcu_expedited=1 rootwait ro "
        "init=/init androidboot.bootdevice=1d84000.ufshc "
        "androidboot.baseband=sdy androidboot.keymaster=1  skip_initramfs "
        "androidboot.serialno=BLAHBLAHBLAH androidboot.slot_suffix=_a "
        "androidboot.hardware.platform=sdw813 androidboot.hardware=foo "
        "androidboot.revision=EVT1.0 androidboot.bootloader=burp-0.1-7521 "
        "androidboot.hardware.sku=mary androidboot.hardware.radio.subtype=0 "
        "androidboot.dtbo_idx=2 androidboot.mode=normal "
        "androidboot.hardware.ddr=1GB,combuchi,LPDDR4X "
        "androidboot.ddr_info=combuchiandroidboot.ddr_size=2GB "
        "androidboot.hardware.ufs=2GB,combushi "
        "androidboot.boottime=0BLE:58,1BLL:22,1BLE:571,2BLL:105,ODT:0,AVB:123 "
        "androidboot.ramdump=disabled "
        "dm=\"1 vroot none ro 1,0 10416 verity 1 624684 fec_start 624684\" "
        "root=/dev/dm-0 "
        "androidboot.vbmeta.device=PARTUUID=aa08f1a4-c7c9-402e-9a66-9707cafa9ceb "
        "androidboot.vbmeta.avb_version=\"1.1\" "
        "androidboot.vbmeta.device_state=unlocked "
        "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=5248 "
        "androidboot.vbmeta.digest="
        "ac13147e959861c20f2a6da97d25fe79e60e902c022a371c5c039d31e7c68860 "
        "androidboot.vbmeta.invalidate_on_error=yes "
        "androidboot.veritymode=enforcing androidboot.verifiedbootstate=orange "
        "androidboot.space=\"sha256 5248 androidboot.nospace=nope\" "
        "printk.devkmsg=on msm_rtb.filter=0x237 ehci-hcd.park=3 "
        "service_locator.enable=1 firmware_class.path=/vendor/firmware "
        "cgroup.memory=nokmem lpm_levels.sleep_disabled=1 "
        "buildvariant=userdebug  console=null";

const std::vector<std::string> result = {
        "rcupdate.rcu_expedited=1",
        "rootwait",
        "ro",
        "init=/init",
        "androidboot.bootdevice=1d84000.ufshc",
        "androidboot.baseband=sdy",
        "androidboot.keymaster=1",
        "",
        "skip_initramfs",
        "androidboot.serialno=BLAHBLAHBLAH",
        "androidboot.slot_suffix=_a",
        "androidboot.hardware.platform=sdw813",
        "androidboot.hardware=foo",
        "androidboot.revision=EVT1.0",
        "androidboot.bootloader=burp-0.1-7521",
        "androidboot.hardware.sku=mary",
        "androidboot.hardware.radio.subtype=0",
        "androidboot.dtbo_idx=2",
        "androidboot.mode=normal",
        "androidboot.hardware.ddr=1GB,combuchi,LPDDR4X",
        "androidboot.ddr_info=combuchiandroidboot.ddr_size=2GB",
        "androidboot.hardware.ufs=2GB,combushi",
        "androidboot.boottime=0BLE:58,1BLL:22,1BLE:571,2BLL:105,ODT:0,AVB:123",
        "androidboot.ramdump=disabled",
        "dm=1 vroot none ro 1,0 10416 verity 1 624684 fec_start 624684",
        "root=/dev/dm-0",
        "androidboot.vbmeta.device=PARTUUID=aa08f1a4-c7c9-402e-9a66-9707cafa9ceb",
        "androidboot.vbmeta.avb_version=1.1",
        "androidboot.vbmeta.device_state=unlocked",
        "androidboot.vbmeta.hash_alg=sha256",
        "androidboot.vbmeta.size=5248",
        "androidboot.vbmeta.digest="
        "ac13147e959861c20f2a6da97d25fe79e60e902c022a371c5c039d31e7c68860",
        "androidboot.vbmeta.invalidate_on_error=yes",
        "androidboot.veritymode=enforcing",
        "androidboot.verifiedbootstate=orange",
        "androidboot.space=sha256 5248 androidboot.nospace=nope",
        "printk.devkmsg=on",
        "msm_rtb.filter=0x237",
        "ehci-hcd.park=3",
        "service_locator.enable=1",
        "firmware_class.path=/vendor/firmware",
        "cgroup.memory=nokmem",
        "lpm_levels.sleep_disabled=1",
        "buildvariant=userdebug",
        "",
        "console=null",
};

}  // namespace

TEST(fs_mgr, SplitWithQuote) {
    EXPECT_EQ(result, __for_testing_only__SplitWithQuote(cmdline, " "));
}

TEST(fs_mgr, fs_mgr_get_boot_config_from_kernel_cmdline) {
    std::string content;
    for (auto& str : result) {
        static constexpr char androidboot[] = "androidboot.";
        if (!android::base::StartsWith(str, androidboot)) continue;
        auto equal_sign = str.find('=');
        if (equal_sign == str.npos) {
            EXPECT_FALSE(__for_testing_only__fs_mgr_get_boot_config_from_kernel(
                    cmdline, str.substr(strlen(androidboot)), &content));
            EXPECT_TRUE(content.empty()) << content;
        } else {
            EXPECT_TRUE(__for_testing_only__fs_mgr_get_boot_config_from_kernel(
                    cmdline, str.substr(strlen(androidboot), equal_sign - strlen(androidboot)),
                    &content))
                    << " for " << str;
            EXPECT_EQ(str.substr(equal_sign + 1), content);
        }
    }
    EXPECT_FALSE(__for_testing_only__fs_mgr_get_boot_config_from_kernel(
            cmdline, "vbmeta.avb_versio", &content));
    EXPECT_TRUE(content.empty()) << content;
    EXPECT_FALSE(
            __for_testing_only__fs_mgr_get_boot_config_from_kernel(cmdline, "nospace", &content));
    EXPECT_TRUE(content.empty()) << content;
}

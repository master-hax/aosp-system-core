#
# Copyright 2017 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

ifndef BOARD_VNDK_VERSION

# These are required since *.vendor variant is only available when
# BOARD_VNDK_VERSION is set. For devices where BOARD_VNDK_VERSION
# is not set (i.e. marlin/sailfish), these *.vendor variant for
# grep and sh are explicitly defined.

include $(CLEAR_VARS)
LOCAL_MODULE := sh.vendor
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_PATH := external/mksh
LOCAL_PREBUILT_MODULE_FILE := out/soong/.intermediates/$(LOCAL_PATH)/sh/android_$(TARGET_ARCH)_$(TARGET_ARCH_VARIANT)_$(TARGET_CPU_VARIANT)_core/sh
LOCAL_MODULE_TARGET_ARCH := $(TARGET_ARCH)
LOCAL_VENDOR_MODULE := true
LOCAL_MODULE_PATH := $(PRODUCT_OUT)/vendor/bin
LOCAL_MODULE_STEM := sh
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := grep.vendor
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_PATH := system/core/toolbox
LOCAL_PREBUILT_MODULE_FILE := out/soong/.intermediates/$(LOCAL_PATH)/grep/android_$(TARGET_ARCH)_$(TARGET_ARCH_VARIANT)_$(TARGET_CPU_VARIANT)_core/grep
LOCAL_MODULE_TARGET_ARCH := $(TARGET_ARCH)
LOCAL_VENDOR_MODULE := true
LOCAL_MODULE_PATH := $(PRODUCT_OUT)/vendor/bin
LOCAL_MODULE_STEM := grep
LOCAL_MODULE_SYMLINKS := egrep fgrep
include $(BUILD_PREBUILT)

endif # BOARD_VNDK_VERSION is not set

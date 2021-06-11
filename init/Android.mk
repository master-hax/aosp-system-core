# Copyright 2005 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

-include system/sepolicy/policy_version.mk

# --

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
init_options += \
    -DALLOW_FIRST_STAGE_CONSOLE=1 \
    -DALLOW_LOCAL_PROP_OVERRIDE=1 \
    -DALLOW_PERMISSIVE_SELINUX=1 \
    -DREBOOT_BOOTLOADER_ON_PANIC=1 \
    -DWORLD_WRITABLE_KMSG=1 \
    -DDUMP_ON_UMOUNT_FAILURE=1
else
init_options += \
    -DALLOW_FIRST_STAGE_CONSOLE=0 \
    -DALLOW_LOCAL_PROP_OVERRIDE=0 \
    -DALLOW_PERMISSIVE_SELINUX=0 \
    -DREBOOT_BOOTLOADER_ON_PANIC=0 \
    -DWORLD_WRITABLE_KMSG=0 \
    -DDUMP_ON_UMOUNT_FAILURE=0
endif

ifneq (,$(filter eng,$(TARGET_BUILD_VARIANT)))
init_options += \
    -DSHUTDOWN_ZERO_TIMEOUT=1
else
init_options += \
    -DSHUTDOWN_ZERO_TIMEOUT=0
endif

init_options += -DLOG_UEVENTS=0 \
    -DSEPOLICY_VERSION=$(POLICYVERS)

init_cflags += \
    $(init_options) \
    -Wall -Wextra \
    -Wno-unused-parameter \
    -Werror \

include $(CLEAR_VARS)

LOCAL_MODULE := init_system
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
LOCAL_REQUIRED_MODULES := \
   init_second_stage \

include $(BUILD_PHONY_PACKAGE)

include $(CLEAR_VARS)

LOCAL_MODULE := init_vendor
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
ifneq ($(BOARD_BUILD_SYSTEM_ROOT_IMAGE),true)
ifneq ($(BOARD_USES_RECOVERY_AS_BOOT),true)
LOCAL_REQUIRED_MODULES := \
   init_first_stage \

endif  # BOARD_USES_RECOVERY_AS_BOOT
endif  # BOARD_BUILD_SYSTEM_ROOT_IMAGE
include $(BUILD_PHONY_PACKAGE)

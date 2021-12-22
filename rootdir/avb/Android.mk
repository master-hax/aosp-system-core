LOCAL_PATH:= $(call my-dir)

ifeq ($(BOARD_MOVE_GSI_AVB_KEYS_TO_VENDOR_BOOT),true) # AVB keys are installed to vendor ramdisk
  ifeq ($(BOARD_MOVE_RECOVERY_RESOURCES_TO_VENDOR_BOOT),true) # no dedicated recovery partition
    my_gsi_avb_keys_path := $(TARGET_VENDOR_RAMDISK_OUT)/first_stage_ramdisk/avb
  else # device has a dedicated recovery partition
    my_gsi_avb_keys_path := $(TARGET_VENDOR_RAMDISK_OUT)/avb
  endif
else
  ifeq ($(BOARD_USES_RECOVERY_AS_BOOT),true) # no dedicated recovery partition
    my_gsi_avb_keys_path := $(TARGET_RECOVERY_ROOT_OUT)/first_stage_ramdisk/avb
  else # device has a dedicated recovery partition
    my_gsi_avb_keys_path := $(TARGET_RAMDISK_OUT)/avb
  endif
endif

#######################################
# q-gsi.avbpubkey
include $(CLEAR_VARS)

LOCAL_MODULE := q-gsi.avbpubkey
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_MODULE_CLASS := ETC
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_PATH := $(my_gsi_avb_keys_path)

include $(BUILD_PREBUILT)

#######################################
# q-developer-gsi.avbpubkey
include $(CLEAR_VARS)

LOCAL_MODULE := q-developer-gsi.avbpubkey
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_MODULE_CLASS := ETC
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_PATH := $(my_gsi_avb_keys_path)

include $(BUILD_PREBUILT)

#######################################
# r-gsi.avbpubkey
include $(CLEAR_VARS)

LOCAL_MODULE := r-gsi.avbpubkey
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_MODULE_CLASS := ETC
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_PATH := $(my_gsi_avb_keys_path)

include $(BUILD_PREBUILT)

#######################################
# r-developer-gsi.avbpubkey
include $(CLEAR_VARS)

LOCAL_MODULE := r-developer-gsi.avbpubkey
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_MODULE_CLASS := ETC
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_PATH := $(my_gsi_avb_keys_path)

include $(BUILD_PREBUILT)

#######################################
# s-gsi.avbpubkey
include $(CLEAR_VARS)

LOCAL_MODULE := s-gsi.avbpubkey
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_MODULE_CLASS := ETC
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_PATH := $(my_gsi_avb_keys_path)

include $(BUILD_PREBUILT)

#######################################
# s-developer-gsi.avbpubkey
include $(CLEAR_VARS)

LOCAL_MODULE := s-developer-gsi.avbpubkey
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_MODULE_CLASS := ETC
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_PATH := $(my_gsi_avb_keys_path)

include $(BUILD_PREBUILT)
<<<<<<< HEAD   (99a5f9 Merge "[automerger skipped] Merge "liblog: use unique log ta)

#######################################
# qcar-gsi.avbpubkey
include $(CLEAR_VARS)

LOCAL_MODULE := qcar-gsi.avbpubkey
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_MODULE_CLASS := ETC
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_PATH := $(my_gsi_avb_keys_path)

include $(BUILD_PREBUILT)

my_gsi_avb_keys_path :=
=======
#######################################
# qcar-gsi.avbpubkey
include $(CLEAR_VARS)

LOCAL_MODULE := qcar-gsi.avbpubkey
LOCAL_MODULE_CLASS := ETC
LOCAL_SRC_FILES := $(LOCAL_MODULE)
ifeq ($(BOARD_USES_RECOVERY_AS_BOOT),true)
LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/first_stage_ramdisk/avb
else
LOCAL_MODULE_PATH := $(TARGET_RAMDISK_OUT)/avb
endif

include $(BUILD_PREBUILT)
>>>>>>> BRANCH (efcca3 Merge "Adding Car GSI public key" into android11-tests-dev)

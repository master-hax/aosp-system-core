
LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := mkbootimg
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_IS_HOST_MODULE := true

LOCAL_MODULE := mkbootimg

include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := extract_bootimg
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_IS_HOST_MODULE := true

LOCAL_MODULE := extract_bootimg

include $(BUILD_PREBUILT)

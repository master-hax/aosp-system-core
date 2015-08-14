LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := lmkd.c
LOCAL_SHARED_LIBRARIES := liblog libm libc libprocessgroup
LOCAL_CFLAGS := -Werror

LOCAL_MODULE := lmkd

LOCAL_REQUIRED_MODULES := lmkd.rc

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE := lmkd.rc
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT)/init

include $(BUILD_PREBUILT)

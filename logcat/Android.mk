# Copyright 2006-2014 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= logcat.cpp event.logtags

LOCAL_SHARED_LIBRARIES := liblog libbase libcutils

LOCAL_MODULE := logcat

LOCAL_CFLAGS := -Werror

LOCAL_REQUIRED_MODULES := logcatd.rc

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE := logcatd.rc
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT)/init

include $(BUILD_PREBUILT)

include $(call first-makefiles-under,$(LOCAL_PATH))

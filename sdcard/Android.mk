LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := sdcard.c
LOCAL_MODULE := sdcard
LOCAL_CFLAGS := -Wall -Wno-unused-parameter -Werror
LOCAL_CFLAGS += -fno-strict-aliasing

LOCAL_SHARED_LIBRARIES := libcutils

include $(BUILD_EXECUTABLE)

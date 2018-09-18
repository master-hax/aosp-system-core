# Copyright 2018 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)
LOCAL_CPPFLAGS := -Wall -Wextra -Wno-unused-parameter -Werror -std=gnu++1z
LOCAL_SRC_FILES := ucontainer.c
LOCAL_MODULE := ucontainer
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_RAMDISK_OUT)
LOCAL_UNSTRIPPED_PATH := $(TARGET_RAMDISK_OUT_UNSTRIPPED)
LOCAL_SANITIZE := signed-integer-overflow
include $(BUILD_EXECUTABLE)

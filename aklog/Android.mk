# Copyright 2012 The Android Open Source Project

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	aklog.c \

LOCAL_MODULE := aklog

LOCAL_MODULE_TAGS := optional

LOCAL_STATIC_LIBRARIES := libc

LOCAL_FORCE_STATIC_EXECUTABLE := true

include $(BUILD_EXECUTABLE)

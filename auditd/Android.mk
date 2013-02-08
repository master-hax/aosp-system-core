# Copyright 2005 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

#TARGET_DEVICE_KERNEL_HEADERS
LOCAL_C_INCLUDES := \
		bionic/kernel/common \
		bionic/kernel/arch-$(TARGET_ARCH)

LOCAL_SRC_FILES:= \
	auditd.c \
	netlink.c \
	libaudit.c \
	audit_log.c

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	libc

LOCAL_MODULE_TAGS:=optional
LOCAL_MODULE:=auditd

include $(BUILD_EXECUTABLE)

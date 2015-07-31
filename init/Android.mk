# Copyright 2005 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

# --

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
init_options += -DALLOW_LOCAL_PROP_OVERRIDE=1 -DALLOW_PERMISSIVE_SELINUX=1
else
init_options += -DALLOW_LOCAL_PROP_OVERRIDE=0 -DALLOW_PERMISSIVE_SELINUX=0
endif

init_options += -DLOG_UEVENTS=0

init_cflags_common += \
    $(init_options) \
    -Wall -Wextra \
    -Wno-unused-parameter \
    -Werror \

# Host builds do not have Android SELinux support. 
init_cflags = $(init_cflags_common) -DINIT_HAVE_SELINUX=1

# --

# If building on Linux, then build unit test for the host.
ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_CPPFLAGS := $(init_cflags_common)
LOCAL_SRC_FILES:= \
    parser/parser.cpp \
    parser/tokenizer.cpp \
    util.cpp \

LOCAL_MODULE := libinit_parser
LOCAL_CLANG := true
LOCAL_SHARED_LIBRARIES := libbase libcutils
include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := init_parser_tests
LOCAL_SRC_FILES := \
    parser/parser_test.cpp \
    parser/tokenizer_test.cpp \

LOCAL_LDLIBS += -lrt
LOCAL_STATIC_LIBRARIES := libinit_parser
LOCAL_CLANG := true
LOCAL_SHARED_LIBRARIES := libbase libcutils
include $(BUILD_HOST_NATIVE_TEST)
endif

include $(CLEAR_VARS)
LOCAL_CPPFLAGS := $(init_cflags)
LOCAL_SRC_FILES:= \
    action.cpp \
    init_parser.cpp \
    log.cpp \
    parser.cpp \
    util.cpp \

LOCAL_STATIC_LIBRARIES := libbase
LOCAL_MODULE := libinit
LOCAL_CLANG := true
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_CPPFLAGS := $(init_cflags)
LOCAL_SRC_FILES:= \
    bootchart.cpp \
    builtins.cpp \
    devices.cpp \
    init.cpp \
    keychords.cpp \
    property_service.cpp \
    signal_handler.cpp \
    ueventd.cpp \
    ueventd_parser.cpp \
    watchdogd.cpp \

LOCAL_MODULE:= init
LOCAL_C_INCLUDES += \
    system/extras/ext4_utils \
    system/core/mkbootimg

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_UNSTRIPPED)

LOCAL_STATIC_LIBRARIES := \
    libinit \
    libfs_mgr \
    libsquashfs_utils \
    liblogwrap \
    libcutils \
    libbase \
    libext4_utils_static \
    libutils \
    liblog \
    libc \
    libselinux \
    libmincrypt \
    libc++_static \
    libdl

# Create symlinks
LOCAL_POST_INSTALL_CMD := $(hide) mkdir -p $(TARGET_ROOT_OUT)/sbin; \
    ln -sf ../init $(TARGET_ROOT_OUT)/sbin/ueventd; \
    ln -sf ../init $(TARGET_ROOT_OUT)/sbin/watchdogd

LOCAL_CLANG := true
include $(BUILD_EXECUTABLE)




include $(CLEAR_VARS)
LOCAL_MODULE := init_tests
LOCAL_SRC_FILES := \
    init_parser_test.cpp \
    util_test.cpp \

LOCAL_SHARED_LIBRARIES += \
    libcutils \
    libbase \

LOCAL_STATIC_LIBRARIES := libinit
LOCAL_CLANG := true
include $(BUILD_NATIVE_TEST)

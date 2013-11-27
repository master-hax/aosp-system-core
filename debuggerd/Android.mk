# Copyright 2005 The Android Open Source Project

ifneq ($(filter arm mips x86,$(TARGET_ARCH)),)

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	backtrace.cpp \
	debuggerd.cpp \
	getevent.cpp \
	tombstone.cpp \
	utility.cpp \
	$(TARGET_ARCH)/machine.cpp \

LOCAL_CONLYFLAGS := -std=gnu99
LOCAL_CPPFLAGS := -std=gnu++11
LOCAL_CFLAGS := \
	-Wall \
	-Wno-array-bounds \
	-Werror \

LOCAL_MODULE := debuggerd

ifeq ($(ARCH_ARM_HAVE_VFP),true)
LOCAL_CFLAGS += -DWITH_VFP
endif # ARCH_ARM_HAVE_VFP
ifeq ($(ARCH_ARM_HAVE_VFP_D32),true)
LOCAL_CFLAGS += -DWITH_VFP_D32
endif # ARCH_ARM_HAVE_VFP_D32

LOCAL_SHARED_LIBRARIES := \
	libbacktrace \
	libc \
	libcutils \
	liblog \
	libselinux \

include external/stlport/libstlport.mk

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := crasher.c
LOCAL_SRC_FILES += $(TARGET_ARCH)/crashglue.S
LOCAL_MODULE := crasher
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS += -fstack-protector-all -Wno-unused-parameter -Wno-free-nonheap-object
#LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_SHARED_LIBRARIES := libcutils liblog libc
include $(BUILD_EXECUTABLE)
RUN_ON_HOST_FLAGS := crash
RUN_ON_HOST_DEPS := $(TARGET_OUT_EXECUTABLES)/debuggerd
RUN_ON_HOST_DIRS := /data/tombstones /data/system
RUN_ON_HOST_PREPARE := \
	rm -rf /data/tombstones/* ; \
	LD_LIBRARY_PATH=$(TARGET_OUT_SHARED_LIBRARIES) $(TARGET_OUT_EXECUTABLES)/debuggerd &
RUN_ON_HOST_FINISH := \
	kill `ps | grep debuggerd | awk '{print $$1}'` ; \
        cat /data/tombstones/tombstone_00
include $(RUN_ON_HOST)

# run test on host

ifeq ($(ARCH_ARM_HAVE_VFP),true)
include $(CLEAR_VARS)

LOCAL_CFLAGS += -DWITH_VFP
ifeq ($(ARCH_ARM_HAVE_VFP_D32),true)
LOCAL_CFLAGS += -DWITH_VFP_D32
endif # ARCH_ARM_HAVE_VFP_D32

LOCAL_SRC_FILES := vfp-crasher.c vfp.S
LOCAL_MODULE := vfp-crasher
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := libcutils liblog libc
include $(BUILD_EXECUTABLE)
endif # ARCH_ARM_HAVE_VFP == true

endif # arm or x86 in TARGET_ARCH

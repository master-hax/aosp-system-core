# Copyright 2005 The Android Open Source Project

ifneq ($(filter arm mips x86,$(TARGET_ARCH)),)

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	backtrace.c \
	debuggerd.c \
	getevent.c \
	tombstone.c \
	utility.c \
	$(TARGET_ARCH)/machine.c

LOCAL_CFLAGS := -Wall -Werror -Wno-unused-parameter -std=gnu99
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

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := crasher.c
LOCAL_SRC_FILES += $(TARGET_ARCH)/crashglue.S
LOCAL_MODULE := crasher
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS += -fstack-protector-all
#LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_SHARED_LIBRARIES := libcutils liblog libc
include $(BUILD_EXECUTABLE)

# run test on host

crasher-run-on-host: crasher $(TARGET_OUT_EXECUTABLES)/$(LINKER) $(TARGET_OUT_EXECUTABLES)/sh $(TARGET_OUT_EXECUTABLES)/debuggerd
	if [ ! -d /system -o ! -d /system/bin ]; then \
	  echo "Attempting to create /system/bin"; \
	  sudo mkdir -p -m 0777 /system/bin; \
	fi
	if [ ! -d /data -o ! -d /data/tombstones ]; then \
	  echo "Attempting to create /data/tombstones"; \
	  sudo mkdir -p -m 0777 /data/tombstones; \
	fi
	if [ ! -d /data/system ]; then \
	  echo "Attempting to create /data/system"; \
	  sudo mkdir -p -m 0777 /data/system; \
	fi
	rm -rf /data/tombstones/*
	mkdir -p $(TARGET_OUT_DATA)/local/tmp
	cp $(TARGET_OUT_EXECUTABLES)/$(LINKER) /system/bin
	cp $(TARGET_OUT_EXECUTABLES)/sh /system/bin
	LD_LIBRARY_PATH=$(TARGET_OUT_SHARED_LIBRARIES) $(TARGET_OUT_EXECUTABLES)/debuggerd &
	sleep 1
	-ANDROID_DATA=$(TARGET_OUT_DATA) \
	ANDROID_ROOT=$(TARGET_OUT) \
	LD_LIBRARY_PATH=$(TARGET_OUT_SHARED_LIBRARIES) \
		$(TARGET_OUT_OPTIONAL_EXECUTABLES)/crasher crash
	kill `ps | grep debuggerd | awk '{print $$1}'`
	cat /data/tombstones/tombstone_00

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

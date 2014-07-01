ifneq ($(BUILD_TINY_ANDROID),true)
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= netcfg.c
LOCAL_MODULE:= netcfg

#LOCAL_FORCE_STATIC_EXECUTABLE := true
#LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT_SBIN)
#LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_SBIN_UNSTRIPPED)
#LOCAL_STATIC_LIBRARIES := libcutils libc

LOCAL_SHARED_LIBRARIES := libc libnetutils
LOCAL_CFLAGS := -Werror
ifeq (true,$(TARGET_PREFER_32_BIT_EXECUTABLES))
# We are doing a 32p build, force recovery to be 64bit
LOCAL_MULTILIB := 64
endif

include $(BUILD_EXECUTABLE)
endif

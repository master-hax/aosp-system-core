ifeq ($(HOST_OS),linux)

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := gpttool.c
LOCAL_STATIC_LIBRARIES := libz
LOCAL_CFLAGS := -Werror

# The code is ignoring read() results.
LOCAL_CFLAGS += -Wno-unused-result

LOCAL_MODULE := gpttool

include $(BUILD_HOST_EXECUTABLE)

endif

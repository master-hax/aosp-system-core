LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CPPFLAGS := -Wall -Wextra -Werror
LOCAL_SRC_FILES := watchdogd.cpp

LOCAL_MODULE := watchdogd

LOCAL_SHARED_LIBRARIES := libbase

# TODO(b/73660730): Hack around this path being used by vendors and remove sbin.
LOCAL_POST_INSTALL_CMD := $(hide) mkdir -p $(TARGET_ROOT_OUT)/sbin; \
    ln -sf ../init $(TARGET_ROOT_OUT)/sbin/watchdogd

LOCAL_SANITIZE := signed-integer-overflow
include $(BUILD_EXECUTABLE)


LOCAL_PATH:= $(call my-dir)

# Shared library for target
# ========================================================
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
  native_bridge.cc

LOCAL_MODULE:= libnativebridge
LOCAL_CPP_EXTENSION := .cc
LOCAL_CFLAGS := -Werror
LOCAL_CPPFLAGS := -std=gnu++11
LOCAL_LDFLAGS := -ldl
LOCAL_MULTILIB := both

include $(BUILD_SHARED_LIBRARY)

# Shared library for host
# ========================================================
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
  native_bridge.cc

LOCAL_MODULE:= libnativebridge
LOCAL_CPP_EXTENSION := .cc
LOCAL_CFLAGS := -Werror
LOCAL_CPPFLAGS := -std=gnu++11
LOCAL_LDFLAGS := -ldl
LOCAL_MULTILIB := both

include $(BUILD_HOST_SHARED_LIBRARY)

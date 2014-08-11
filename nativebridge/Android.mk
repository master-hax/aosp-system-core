LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
  native_bridge.cc

LOCAL_MODULE:= nativebridge
LOCAL_CPP_EXTENSION := .cc

LOCAL_C_INCLUDES += bionic bionic/libstdc++/include external/stlport/stlport
LOCAL_CFLAGS := -Werror

LOCAL_SHARED_LIBRARIES += libstlport
LOCAL_CPPFLAGS := -std=gnu++11
LOCAL_LDFLAGS := -ldl

LOCAL_MULTILIB := both

include $(BUILD_SHARED_LIBRARY)

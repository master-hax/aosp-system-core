LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

# Shared library for target
# ========================================================

LOCAL_MODULE:= libacc
LOCAL_SRC_FILES := acc.cpp

LOCAL_SHARED_LIBRARIES := libdl libcutils

include $(BUILD_SHARED_LIBRARY)

# Build children
# ========================================================

include $(call all-makefiles-under,$(LOCAL_PATH))

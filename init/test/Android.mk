LOCAL_PATH:= $(call my-dir)

# Test service.
# =========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := test_service
LOCAL_SRC_FILES := \
    test_service.cpp \

LOCAL_SHARED_LIBRARIES += \
    libbase

LOCAL_INIT_RC := test_service.rc

LOCAL_CLANG := true
include $(BUILD_EXECUTABLE)

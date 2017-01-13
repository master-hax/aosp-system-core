LOCAL_PATH:= $(call my-dir)

# Dummy adbd used for USB benchmarking.
# Only enabled for userdebug/eng builds.
ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))

include $(CLEAR_VARS)
LOCAL_CLANG := true

LOCAL_SRC_FILES := \
    bench_adbd.cpp

LOCAL_CFLAGS := \
    -Wall \
    -Wextra \
    -Werror \

LOCAL_C_INCLUDES := $(LOCAL_PATH)/..

LOCAL_MODULE := bench_adbd

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_STATIC_LIBRARIES := \
    libcrypto_utils \
    libcrypto \
    libadbd_usb \
    libbase \
    liblog \

include $(BUILD_EXECUTABLE)

# Client for bench_adbd.
include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
    bench_adb.cpp

LOCAL_CFLAGS := \
    -Wall \
    -Wextra \
    -Werror \

LOCAL_C_INCLUDES := $(LOCAL_PATH)/..

LOCAL_MODULE := bench_adb

LOCAL_SHARED_LIBRARIES := \
    libbase \
    liblog \
    libusb \

include $(BUILD_HOST_EXECUTABLE)

endif

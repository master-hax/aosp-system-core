LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

include external/stlport/libstlport.mk
LOCAL_CPP_EXTENSION := .cc

LOCAL_SRC_FILES := \
	zip_archive.h \
	zip_archive.cc

LOCAL_STATIC_LIBRARIES := libz
LOCAL_MODULE:= libziparchive

LOCAL_C_INCLUDES += external/zlib

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := ziparchive-tests
LOCAL_CPP_EXTENSION := .cc
LOCAL_CFLAGS += \
    -DGTEST_OS_LINUX_ANDROID \
    -DGTEST_HAS_STD_STRING
LOCAL_SRC_FILES := zip_archive_test.cc
LOCAL_LDFLAGS := -llog
LOCAL_STATIC_LIBRARIES := libziparchive libz libgtest libgtest_main
include $(BUILD_NATIVE_TEST)

LOCAL_PATH := $(call my-dir)

memunreachable_srcs := \
   Allocator.cpp \
   HeapWalker.cpp \
   LeakPipe.cpp \
   LineBuffer.cpp \
   MemUnreachable.cpp \
   ProcessMappings.cpp \
   PtracerThread.cpp \
   ThreadCapture.cpp \

memunreachable_test_srcs := \
   tests/Allocator_test.cpp \
   tests/HeapWalker_test.cpp \
   tests/MemUnreachable_test.cpp \
   tests/ThreadCapture_test.cpp \

include $(CLEAR_VARS)

LOCAL_MODULE := libmemunreachable
LOCAL_SRC_FILES := $(memunreachable_srcs)
LOCAL_CFLAGS := -std=c++14 -Wall -Wextra -Werror
LOCAL_SHARED_LIBRARIES := libbase liblog
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_CLANG := true

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE := memunreachable_test
LOCAL_SRC_FILES := $(memunreachable_test_srcs)
LOCAL_CFLAGS := -std=c++14 -Wall -Wextra -Werror
LOCAL_CLANG := true
LOCAL_SHARED_LIBRARIES := libmemunreachable libbase

include $(BUILD_NATIVE_TEST)

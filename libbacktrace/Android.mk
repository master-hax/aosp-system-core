LOCAL_PATH:= $(call my-dir)

common_src := \
	common.c \
	demangle.c \
	map_info.c \
	thread.c \
	tid.c \

common_cflags := \
	-Wall \
	-Wno-unused-parameter \
	-Werror \
	-std=gnu99 \

common_shared_libs := \
	libcutils \
	libgccdemangle \
	liblog \

# To enable using libunwind on each arch, add it to the list below.
ifeq ($(TARGET_ARCH),$(filter $(TARGET_ARCH),))

#----------------------------------------------------------------------------
# The libbacktrace library using libunwind
#----------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	$(common_src) \
	unwind.c \
	unwind_remote.c \
	unwind_local.c \

LOCAL_CFLAGS := \
	$(common_cflags) \

LOCAL_MODULE := libbacktrace
LOCAL_MODULE_TAGS := optional

LOCAL_SHARED_LIBRARIES := \
	$(common_shared_libs) \
	libunwind \
	libunwind-ptrace \

LOCAL_C_INCLUDES := \
	external/libunwind/include \
	system/core/libcorkscrew \

LOCAL_ADDITIONAL_DEPENDENCIES := \
	$(LOCAL_PATH)/Android.mk

include $(BUILD_SHARED_LIBRARY)

else

#----------------------------------------------------------------------------
# The libbacktrace library using libcorkscrew
#----------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	$(common_src) \
	corkscrew.c \

LOCAL_CFLAGS := \
	$(common_cflags) \

LOCAL_MODULE := libbacktrace
LOCAL_MODULE_TAGS := optional

LOCAL_C_INCLUDES := \
	system/core/libcorkscrew \

LOCAL_SHARED_LIBRARIES := \
	$(common_shared_libs) \
	libcorkscrew \
	libdl \

LOCAL_ADDITIONAL_DEPENDENCIES := \
	$(LOCAL_PATH)/Android.mk

include $(BUILD_SHARED_LIBRARY)

endif

#----------------------------------------------------------------------------
# libbacktrace test library, all optimizations turned off
#----------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_MODULE := libbacktrace_test
LOCAL_MODULE_FLAGS := debug

LOCAL_SRC_FILES := \
	backtrace_testlib.c

LOCAL_CFLAGS += \
	-std=gnu99 \
	-O0 \

LOCAL_ADDITIONAL_DEPENDENCIES := \
	$(LOCAL_PATH)/Android.mk

include $(BUILD_SHARED_LIBRARY)

#----------------------------------------------------------------------------
# libbacktrace test executable
#----------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_MODULE := backtrace_test
LOCAL_MODULE_FLAGS := debug

LOCAL_SRC_FILES := \
	backtrace_test.cpp \
	tid.c \

LOCAL_CFLAGS += \
	-Wall \
	-Wextra \
	-fno-builtin \
	-fstack-protector-all \
	-O0 \
	-g \
	-DGTEST_OS_LINUX_ANDROID \
	-DGTEST_HAS_STD_STRING \

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	libbacktrace_test \
	libbacktrace \

LOCAL_LDLIBS := \
	-lpthread \

LOCAL_ADDITIONAL_DEPENDENCIES := \
	$(LOCAL_PATH)/Android.mk

include $(BUILD_NATIVE_TEST)

#----------------------------------------------------------------------------
# Only linux-x86 host versions of libbacktrace supported.
#----------------------------------------------------------------------------
ifeq ($(HOST_OS)-$(HOST_ARCH),linux-x86)

#----------------------------------------------------------------------------
# The host libbacktrace library using libcorkscrew
#----------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_SRC_FILES += \
	$(common_src) \
	corkscrew.c \

LOCAL_CFLAGS += \
	$(common_cflags) \

LOCAL_C_INCLUDES := \
	system/core/libcorkscrew \

LOCAL_SHARED_LIBRARIES := \
	libgccdemangle \
	liblog \
	libcorkscrew \

LOCAL_LDLIBS += \
	-ldl \
	-lrt \

LOCAL_MODULE := libbacktrace
LOCAL_MODULE_TAGS := optional

LOCAL_ADDITIONAL_DEPENDENCIES := \
	$(LOCAL_PATH)/Android.mk

include $(BUILD_HOST_SHARED_LIBRARY)

#----------------------------------------------------------------------------
# libbacktrace host test library, all optimizations turned off
#----------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_MODULE := libbacktrace_test
LOCAL_MODULE_FLAGS := debug

LOCAL_SRC_FILES := \
	backtrace_testlib.c

LOCAL_CFLAGS += \
	-std=gnu99 \
	-O0 \

LOCAL_ADDITIONAL_DEPENDENCIES := \
	$(LOCAL_PATH)/Android.mk

include $(BUILD_HOST_SHARED_LIBRARY)

#----------------------------------------------------------------------------
# libbacktrace host test executable
#----------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_MODULE := backtrace_test
LOCAL_MODULE_FLAGS := debug

LOCAL_SRC_FILES := \
	backtrace_test.cpp \
	tid.c \

LOCAL_CFLAGS += \
	-Wall \
	-Wextra \
	-fno-builtin \
	-fstack-protector-all \
	-O0 \
	-g \
	-DGTEST_HAS_STD_STRING \

LOCAL_SHARED_LIBRARIES := \
	libbacktrace_test \
	libbacktrace \

LOCAL_LDLIBS := \
	-lpthread \

LOCAL_ADDITIONAL_DEPENDENCIES := \
	$(LOCAL_PATH)/Android.mk

include $(BUILD_HOST_NATIVE_TEST)

endif # HOST_OS-HOST_ARCH == linux-x86

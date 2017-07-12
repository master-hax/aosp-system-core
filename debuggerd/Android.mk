LOCAL_PATH := $(call my-dir)

ifeq ($(TARGET_ARCH), $(filter $(TARGET_ARCH), arm arm64 x86 x86_64))
include $(CLEAR_VARS)
LOCAL_MODULE := debuggerd_fallback.$(TARGET_ARCH).policy
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT)/etc/seccomp_policy
LOCAL_SRC_FILES := seccomp/debuggerd_fallback.$(TARGET_ARCH).policy
include $(BUILD_PREBUILT)


ifneq (,$(TARGET_2ND_ARCH))
include $(CLEAR_VARS)
LOCAL_MODULE := debuggerd_fallback.$(TARGET_2ND_ARCH).policy
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT)/etc/seccomp_policy
LOCAL_SRC_FILES := seccomp/debuggerd_fallback.$(TARGET_2ND_ARCH).policy
include $(BUILD_PREBUILT)
endif
endif


include $(CLEAR_VARS)
LOCAL_MODULE := debuggerd_fallback_test.$(TARGET_ARCH).policy
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_DATA_NATIVE_TESTS)/debuggerd_test
LOCAL_SRC_FILES := seccomp/debuggerd_fallback_test.$(TARGET_ARCH).policy
include $(BUILD_PREBUILT)


ifneq (,$(TARGET_2ND_ARCH))
include $(CLEAR_VARS)
LOCAL_MODULE := debuggerd_fallback_test.$(TARGET_2ND_ARCH).policy
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(2ND_TARGET_OUT_DATA_NATIVE_TESTS)/debuggerd_test
LOCAL_SRC_FILES := seccomp/debuggerd_fallback_test.$(TARGET_2ND_ARCH).policy
include $(BUILD_PREBUILT)
endif


include $(CLEAR_VARS)
LOCAL_MODULE := debuggerd_test

LOCAL_CFLAGS := -Wall -Wextra -Werror -Wno-nullability-completeness -Wno-missing-field-initializers
LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)32
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64

LOCAL_SRC_FILES := \
    libdebuggerd/test/dump_memory_test.cpp \
    libdebuggerd/test/elf_fake.cpp \
    libdebuggerd/test/log_fake.cpp \
    libdebuggerd/test/open_files_list_test.cpp \
    libdebuggerd/test/property_fake.cpp \
    libdebuggerd/test/ptrace_fake.cpp \
    libdebuggerd/test/tombstone_test.cpp \
    client/debuggerd_client_test.cpp \
    debuggerd_test.cpp \

LOCAL_SHARED_LIBRARIES := \
    libbacktrace \
    libbase \
    libcutils \
    libdebuggerd_client \
    liblog \
    libminijail \
    libnativehelper \

LOCAL_STATIC_LIBRARIES := \
    libasync_safe \
    libdebuggerd \
    libtombstoned_client_static \

LOCAL_REQUIRED_MODULES := debuggerd_fallback_test.$(TARGET_ARCH).policy

ifneq (,$(TARGET_2ND_ARCH))
LOCAL_REQUIRED_MODULES += debuggerd_fallback_test.$(TARGET_2ND_ARCH).policy
endif

LOCAL_C_INCLUDES := libdebuggerd

include $(BUILD_NATIVE_TEST)

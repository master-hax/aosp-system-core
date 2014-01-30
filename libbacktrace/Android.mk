LOCAL_PATH:= $(call my-dir)

common_cflags := \
	-Wall \
	-Werror \

common_conlyflags := \
	-std=gnu99 \

common_cppflags := \
	-std=gnu++11 \

build_host := false
ifeq ($(HOST_OS),linux)
ifeq ($(HOST_ARCH),$(filter $(HOST_ARCH),x86 x86_64))
build_host := true
endif
endif

# Function to build a target
# $(1): module
# $(2): module tag
# $(3): build type (host or target)
# $(4): build target (SHARED_LIBRARY, NATIVE_TEST, etc)
define build
  module := $(1)
  module_tag := $(2)
  build_type := $(3)
  build_target := $(4)

  include $(CLEAR_VARS)

  LOCAL_MODULE := $$(module)
  LOCAL_MODULE_TAGS := $$(module_tag)

  LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk

  LOCAL_CFLAGS := \
    $$(common_cflags) \
    $$($$(module)_cflags) \
    $$($$(module)_cflags_$$(build_type)) \

  LOCAL_CONLYFLAGS += \
    $$(common_conlyflags) \
    $$($$(module)_conlyflags) \
    $$($$(module)_conlyflags_$$(build_type)) \

  LOCAL_CPPFLAGS += \
    $$(common_cppflags) \
    $$($$(module)_cppflags) \
    $$($$(module)_cppflags_$$(build_type)) \

  LOCAL_C_INCLUDES := \
    $$(common_c_includes) \
    $$($$(module)_c_includes) \
    $$($$(module)_c_includes_$$(build_type)) \

  LOCAL_SRC_FILES := \
    $$($$(module)_src_files) \
    $$($$(module)_src_files_$$(build_type)) \

  LOCAL_STATIC_LIBRARIES := \
    $$($$(module)_static_libraries) \
    $$($$(module)_static_libraries_$$(build_type)) \

  LOCAL_SHARED_LIBRARIES := \
    $$($$(module)_shared_libraries) \
    $$($$(module)_shared_libraries_$$(build_type)) \

  LOCAL_LDLIBS := \
    $$($$(module)_ldlibs) \
    $$($$(module)_ldlibs_$$(build_type)) \

  ifeq ($$(build_type),target)
    include external/stlport/libstlport.mk

    include $$(BUILD_$$(build_target))
  endif

  ifeq ($$(build_type),host)
    # Only build if host builds are supported.
    ifeq ($$(build_host),true)
      include $$(BUILD_HOST_$$(build_target))
    endif
  endif
endef

#-------------------------------------------------------------------------
# The libbacktrace library.
#-------------------------------------------------------------------------
libbacktrace_src_files := \
	BacktraceImpl.cpp \
	BacktraceMap.cpp \
	BacktraceThread.cpp \
	thread_utils.c \

libbacktrace_shared_libraries_target := \
	libcutils \
	libgccdemangle \

# To enable using libunwind on each arch, add it to this list.
libunwind_architectures := arm arm64 x86

ifeq ($(TARGET_ARCH),$(filter $(TARGET_ARCH),$(libunwind_architectures)))
libbacktrace_src_files += \
	UnwindCurrent.cpp \
	UnwindMap.cpp \
	UnwindPtrace.cpp \

libbacktrace_c_includes := \
	external/libunwind/include \

libbacktrace_shared_libraries := \
	libunwind \
	libunwind-ptrace \

libbacktrace_shared_libraries_host := \
	liblog \

libbacktrace_static_libraries_host := \
	libcutils \

else
libbacktrace_src_files += \
	Corkscrew.cpp \

libbacktrace_c_includes := \
	system/core/libcorkscrew \

libbacktrace_shared_libraries := \
	libcorkscrew \

libbacktrace_shared_libraries_target += \
	libdl \

libbacktrace_ldlibs_host := \
	-ldl \

endif

$(eval $(call build,libbacktrace,optional,target,SHARED_LIBRARY))
$(eval $(call build,libbacktrace,optional,host,SHARED_LIBRARY))

#-------------------------------------------------------------------------
# The libbacktrace_test library needed by backtrace_test.
#-------------------------------------------------------------------------
libbacktrace_test_cflags := \
	-O0 \

libbacktrace_test_src_files := \
	backtrace_testlib.c \

$(eval $(call build,libbacktrace_test,debug,target,SHARED_LIBRARY))
$(eval $(call build,libbacktrace_test,debug,host,SHARED_LIBRARY))

#-------------------------------------------------------------------------
# The backtrace_test executable.
#-------------------------------------------------------------------------
backtrace_test_cflags := \
	-fno-builtin \
	-O0 \
	-g \
	-DGTEST_HAS_STD_STRING \

ifneq ($(TARGET_ARCH),arm64)
backtrace_test_cflags += -fstack-protector-all
else
  $(info TODO: $(LOCAL_PATH)/Android.mk -fstack-protector not yet available for the AArch64 toolchain)
  common_cflags += -fno-stack-protector
endif # arm64

backtrace_test_cflags_target := \
	-DGTEST_OS_LINUX_ANDROID \

backtrace_test_src_files := \
	backtrace_test.cpp \
	thread_utils.c \

backtrace_test_ldlibs := \
	-lpthread \

backtrace_test_ldlibs_host := \
	-lrt \

backtrace_test_shared_libraries := \
	libbacktrace_test \
	libbacktrace \

backtrace_test_shared_libraries_target := \
	libcutils \

$(eval $(call build,backtrace_test,debug,target,NATIVE_TEST))
$(eval $(call build,backtrace_test,debug,host,NATIVE_TEST))

#----------------------------------------------------------------------------
# Special truncated libbacktrace library for mac.
#----------------------------------------------------------------------------
ifeq ($(HOST_OS),darwin)
LOCAL_SRC_FILES := \
	BacktraceMap.cpp \

include $(BUILD_HOST_SHARED_LIBRARY)
endif # HOST_OS-darwin

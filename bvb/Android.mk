#
# Copyright (C) 2016 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_PATH := $(my-dir)

bvb_common_cflags := \
    -D_FILE_OFFSET_BITS=64 \
    -D_POSIX_C_SOURCE=199309L \
    -Wa,--noexecstack \
    -Wall \
    -Wextra \
    -Wformat=2 \
    -Wno-psabi \
    -Wno-unused-parameter \
    -ffunction-sections \
    -fstack-protector-strong \
    -fvisibility=hidden
bvb_common_cppflags := \
    -Wnon-virtual-dtor \
    -fno-strict-aliasing \
    -std=gnu++11
bvb_common_ldflags := \
    -Wl,--gc-sections

include $(CLEAR_VARS)
LOCAL_SRC_FILES := bvbtool
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_IS_HOST_MODULE := true
LOCAL_MODULE := bvbtool
include $(BUILD_PREBUILT)

ifeq ($(HOST_OS),linux)
# Build for the host.
include $(CLEAR_VARS)
LOCAL_MODULE := libbvb_refimpl
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_CPP_EXTENSION := .cc
LOCAL_RTTI_FLAG := -frtti
LOCAL_CLANG := true
LOCAL_CFLAGS := $(bvb_common_cflags) -DBVB_ENABLE_DEBUG
LOCAL_CPPFLAGS := $(bvb_common_cppflags)
LOCAL_LDFLAGS := $(bvb_common_ldflags)
LOCAL_C_INCLUDES :=
LOCAL_SRC_FILES := \
	bvb_property.c \
	bvb_rsa.c \
	bvb_sha256.c \
	bvb_sha512.c \
	bvb_sysdeps_stub.c \
	bvb_util.c \
	bvb_verify.c
include $(BUILD_HOST_STATIC_LIBRARY)
endif  # HOST_OS == linux

include $(CLEAR_VARS)
LOCAL_MODULE := libbvb_refimpl_unittest
LOCAL_MODULE_HOST_OS := linux
LOCAL_CPP_EXTENSION := .cc
LOCAL_RTTI_FLAG := -frtti
LOCAL_CLANG := true
LOCAL_CFLAGS := $(bvb_common_cflags)
LOCAL_CPPFLAGS := $(bvb_common_cppflags)
LOCAL_LDFLAGS := $(bvb_common_ldflags)
LOCAL_C_INCLUDES := external/gtest/include
LOCAL_STATIC_LIBRARIES := \
    libbvb_refimpl \
    libgmock_host \
    libgtest_host
LOCAL_SHARED_LIBRARIES := \
	libchrome
LOCAL_SRC_FILES := bvb_util_unittest.cc bvb_verify_unittest.cc bvbtool_unittest.cc
LOCAL_LDLIBS_linux := -lrt
include $(BUILD_HOST_NATIVE_TEST)

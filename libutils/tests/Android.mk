#
# Copyright (C) 2014 The Android Open Source Project
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

# Build the unit tests.
LOCAL_PATH := $(call my-dir)

libutils_test_srcs := \
    BasicHashtable_test.cpp \
    BlobCache_test.cpp \
    BitSet_test.cpp \
    file_test.cpp \
    LruCache_test.cpp \
    String8_test.cpp \
    stringprintf_test.cpp \
    strings_test.cpp \
    Unicode_test.cpp \
    Vector_test.cpp \

libutils_test_shlibs := \
    liblog \
    libutils \

include $(CLEAR_VARS)
LOCAL_MODULE := libutils_tests
LOCAL_SRC_FILES := $(libutils_test_srcs) Looper_test.cpp
LOCAL_SHARED_LIBRARIES := $(libutils_test_shlibs) libcutils libz
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_MODULE := libutils_tests
LOCAL_SRC_FILES := $(libutils_test_srcs)
ifeq ($(HOST_OS),linux)
LOCAL_SRC_FILES += Looper_test.cpp
endif
LOCAL_STATIC_LIBRARIES := libcutils
LOCAL_SHARED_LIBRARIES := $(libutils_test_shlibs) libz-host
include $(BUILD_HOST_NATIVE_TEST)

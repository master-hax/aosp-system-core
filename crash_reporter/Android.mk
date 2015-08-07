# Copyright (C) 2015 The Android Open Source Project
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

LOCAL_PATH := $(call my-dir)

ifeq ($(HOST_OS),linux)

crash_reporter_cpp_extension := .cc

crash_reporter_src := crash_collector.cc \
    kernel_collector.cc \
    kernel_warning_collector.cc \
    udev_collector.cc \
    unclean_shutdown_collector.cc \
    user_collector.cc

crash_reporter_includes := external/gtest/include

crash_reporter_test_src := crash_collector_test.cc \
    crash_reporter_logs_test.cc \
    kernel_collector_test.cc \
    testrunner.cc \
    udev_collector_test.cc \
    unclean_shutdown_collector_test.cc \
    user_collector_test.cc

warn_collector_src := warn_collector.l

# Crash reporter static library.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libcrash
LOCAL_CPP_EXTENSION := $(crash_reporter_cpp_extension)
LOCAL_C_INCLUDES := $(crash_reporter_includes)
LOCAL_RTTI_FLAG := -frtti
LOCAL_SHARED_LIBRARIES := libchrome libchromeos libdbus libmetrics libpcrecpp
LOCAL_SRC_FILES := $(crash_reporter_src)
include $(BUILD_STATIC_LIBRARY)

# Crash reporter client.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := crash_reporter
LOCAL_CPP_EXTENSION := $(crash_reporter_cpp_extension)
LOCAL_C_INCLUDES := $(crash_reporter_includes)
LOCAL_RTTI_FLAG := -frtti
LOCAL_SHARED_LIBRARIES := libchrome libchromeos libdbus libmetrics libpcrecpp
LOCAL_SRC_FILES := crash_reporter.cc
LOCAL_STATIC_LIBRARIES := libcrash
include $(BUILD_EXECUTABLE)

# Warn collector client.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := warn_collector
LOCAL_CPP_EXTENSION := $(crash_reporter_cpp_extension)
LOCAL_SHARED_LIBRARIES := libmetrics
LOCAL_SRC_FILES := $(warn_collector_src)
include $(BUILD_EXECUTABLE)

# Crash reporter tests.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := crash_reporter_tests
LOCAL_CPP_EXTENSION := $(crash_reporter_cpp_extension)
LOCAL_SHARED_LIBRARIES := libchrome libchromeos libdbus libpcrecpp
LOCAL_SRC_FILES := $(crash_reporter_test_src)
LOCAL_STATIC_LIBRARIES := libcrash libgmock
include $(BUILD_NATIVE_TEST)

endif # HOST_OS == linux

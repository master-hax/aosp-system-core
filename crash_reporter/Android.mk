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

warn_collector_includes := external/gtest/include \
    external/libchrome \
    external/libchromeos/chromeos \
    system/core/metrics/include


# Crash reporter static library.
# ========================================================
include $(CLEAR_VARS)
LOCAL_CPP_EXTENSION := $(crash_reporter_cpp_extension)
LOCAL_SRC_FILES := $(crash_reporter_src)
LOCAL_C_INCLUDES := $(crash_reporter_includes)
LOCAL_MODULE := libcrash
LOCAL_SHARED_LIBRARIES := libchrome libchromeos libdbus libmetrics libpcrecpp
LOCAL_RTTI_FLAG := -frtti
include $(BUILD_STATIC_LIBRARY)

# Crash reporter client.
# ========================================================
include $(CLEAR_VARS)
LOCAL_CPP_EXTENSION := $(crash_reporter_cpp_extension)
LOCAL_SRC_FILES := crash_reporter.cc
LOCAL_C_INCLUDES := $(crash_reporter_includes)
LOCAL_MODULE := crash_reporter
LOCAL_SHARED_LIBRARIES := libchrome libchromeos libdbus libmetrics libpcrecpp
LOCAL_STATIC_LIBRARIES := libcrash
LOCAL_RTTI_FLAG := -frtti
include $(BUILD_EXECUTABLE)

# Warn collector client.
# ========================================================
include $(CLEAR_VARS)
LOCAL_CPP_EXTENSION := $(crash_reporter_cpp_extension)
LOCAL_SRC_FILES := $(warn_collector_src)
LOCAL_C_INCLUDES := $(warn_collector_includes)
LOCAL_MODULE := warn_collector
include $(BUILD_EXECUTABLE)

# Crash reporter tests.
# ========================================================
include $(CLEAR_VARS)
LOCAL_CPP_EXTENSION := $(crash_reporter_cpp_extension)
LOCAL_SRC_FILES := $(crash_reporter_test_src)
LOCAL_MODULE := crash_reporter_tests
LOCAL_SHARED_LIBRARIES := libchrome libchromeos libdbus libpcrecpp
LOCAL_STATIC_LIBRARIES := libcrash libgmock
include $(BUILD_NATIVE_TEST)

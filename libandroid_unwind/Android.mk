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

LOCAL_PATH:= $(call my-dir)

android_unwind_cflags := \
    -ftrapv \
    -Wall \
    -Werror \
    -Wextra \
    -O0 \
    -g \

android_unwind_src_files := \
    ArmUnwind.cpp \
    DwarfCfa.cpp \
    DwarfOp.cpp \
    Elf.cpp \
    ElfInterface.cpp \
    ElfInterfaceArm.cpp \
    Log.cpp \
    Machine.cpp \
    Maps.cpp \
    Memory.cpp \

android_unwind_shared_libraries := \
    libbase \
    liblog \

android_unwind_test_libraries := \
    libbase \

android_unwind_test_src_files := \
    tests/ArmUnwindDecodeTest.cpp \
    tests/ArmUnwindExtractTest.cpp \
    tests/DwarfCfaTest.cpp \
    tests/ElfInterfaceArmTest.cpp \
    tests/ElfInterfaceTest.cpp \
    tests/ElfTest.cpp \
    tests/LogFake.cpp \
    tests/MapsTest.cpp \
	tests/MemoryByPidTest.cpp \
    tests/MemoryFileTest.cpp \
    tests/MemoryFake.cpp \

#    tests/DwarfOpTest.cpp \

# libandroid_unwind
include $(CLEAR_VARS)

LOCAL_MODULE := libandroid_unwind
LOCAL_SRC_FILES := $(android_unwind_src_files)
LOCAL_CFLAGS := $(android_unwind_cflags)
LOCAL_SHARED_LIBRARIES := $(android_unwind_shared_libraries)

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE := libandroid_unwind
LOCAL_SRC_FILES := $(android_unwind_src_files)
LOCAL_CFLAGS := $(android_unwind_cflags)
LOCAL_SHARED_LIBRARIES := $(android_unwind_shared_libraries)

include $(BUILD_HOST_STATIC_LIBRARY)

# libandroid_unwind_with_log
include $(CLEAR_VARS)

LOCAL_MODULE := libandroid_unwind_with_log
LOCAL_SRC_FILES := $(android_unwind_src_files)
LOCAL_CFLAGS := $(android_unwind_cflags) -DLOGGING_ENABLE_OP
LOCAL_SHARED_LIBRARIES := $(android_unwind_shared_libraries)

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE := libandroid_unwind_with_log
LOCAL_SRC_FILES := $(android_unwind_src_files)
LOCAL_CFLAGS := $(android_unwind_cflags) -DLOGGING_ENABLE_OP
LOCAL_SHARED_LIBRARIES := $(android_unwind_shared_libraries)

include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE := libandroid_unwind_with_log_test
LOCAL_SRC_FILES := $(android_unwind_test_src_files)
LOCAL_CFLAGS := $(android_unwind_test_cflags) -DLOGGING_ENABLE_OP
LOCAL_SHARED_LIBRARIES := $(android_unwind_test_libraries) libandroid_unwind_with_log

include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)

LOCAL_MODULE := libandroid_unwind_test
LOCAL_SRC_FILES := $(android_unwind_test_src_files)
LOCAL_CFLAGS := $(android_unwind_test_cflags)
LOCAL_SHARED_LIBRARIES := $(android_unwind_test_libraries) libandroid_unwind

include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)

LOCAL_MODULE := libandroid_unwind_with_log_test
LOCAL_SRC_FILES := $(android_unwind_test_src_files)
LOCAL_CFLAGS := $(android_unwind_test_cflags) -DLOGGING_ENABLE_OP
LOCAL_STATIC_LIBRARIES := $(android_unwind_test_libraries) libandroid_unwind_with_log
LOCAL_LDLIBS := -lrt

include $(BUILD_HOST_NATIVE_TEST)

include $(CLEAR_VARS)

LOCAL_MODULE := libandroid_unwind_test
LOCAL_SRC_FILES := $(android_unwind_test_src_files)
LOCAL_CFLAGS := $(android_unwind_test_cflags)
LOCAL_STATIC_LIBRARIES := $(android_unwind_test_libraries) libandroid_unwind
LOCAL_LDLIBS := -lrt

include $(BUILD_HOST_NATIVE_TEST)


include $(CLEAR_VARS)

LOCAL_MODULE := unwind_info
LOCAL_SRC_FILES := $(android_unwind_src_files) \
	unwind_info.cpp \

LOCAL_CFLAGS := \
    $(android_unwind_cflags) \
    -DLOGGING_ENABLE_OP \
    -DLOGGING_SKIP_EXECUTION \
    -DLOGGING_PRINT \

LOCAL_STATIC_LIBRARIES := \
    libbase \
    liblog \

include $(BUILD_HOST_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE := unwind
LOCAL_SRC_FILES := $(android_unwind_src_files) \
	unwind.cpp \

LOCAL_CFLAGS := $(android_unwind_cflags) \

LOCAL_STATIC_LIBRARIES := \
    libbase \
    liblog \

include $(BUILD_HOST_EXECUTABLE)

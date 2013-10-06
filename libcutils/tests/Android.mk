LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libcutils_test
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := EXECUTABLES

intermediates:= $(local-intermediates-dir)

all_test_files := $(LOCAL_PATH)/string.c
all_tests.c := $(intermediates)/all_tests.c
$(all_tests.c): $(all_test_files) $(LOCAL_PATH)/cutest/CuTest.h $(LOCAL_PATH)/cutest/CuTest.c $(LOCAL_PATH)/cutest/make-tests.sh
	mkdir -p $(dir $@)
	system/core/libcutils/tests/cutest/make-tests.sh $(all_test_files) > $@

LOCAL_GENERATED_SOURCES := \
		$(all_tests.c)

LOCAL_SRC_FILES := \
	cutest/CuTest.c \
	cutest/make-tests.sh \
	string.c

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/cutest

LOCAL_SHARED_LIBRARIES := libcutils

include $(BUILD_EXECUTABLE)

include $(all-subdir-makefiles)

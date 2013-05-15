# Copyright 2006-2014 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= logcat.cpp event.logtags

LOCAL_SHARED_LIBRARIES := liblog

LOCAL_MODULE := logcat

LOCAL_CFLAGS := -Werror

include $(BUILD_EXECUTABLE)

SYMLINK := $(TARGET_OUT)/bin/lolcat
$(SYMLINK): LOGCAT_BINARY := $(LOCAL_MODULE)
$(SYMLINK): $(LOCAL_INSTALLED_MODULE) $(LOCAL_PATH)/Android.mk
	@echo "Symlink: $@ -> $(LOGCAT_BINARY)"
	@mkdir -p $(dir $@)
	@rm -rf $@
	$(hide) ln -sf $(LOGCAT_BINARY) $@

ALL_DEFAULT_INSTALLED_MODULES += $(SYMLINK)

include $(call first-makefiles-under,$(LOCAL_PATH))

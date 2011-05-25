LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

# Buffer should be large enough to hold the content of the package database file
ifneq (,$(PACKAGES_LIST_BUFFER_SIZE))
  LOCAL_CFLAGS += -DPACKAGES_LIST_BUFFER_SIZE=$(PACKAGES_LIST_BUFFER_SIZE)
endif

LOCAL_SRC_FILES:= run-as.c package.c

LOCAL_MODULE:= run-as

LOCAL_FORCE_STATIC_EXECUTABLE := true

LOCAL_STATIC_LIBRARIES := libc

include $(BUILD_EXECUTABLE)

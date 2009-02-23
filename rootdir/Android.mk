LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

# files that live under /system/etc/...

copy_from := \
	etc/mountd.conf \
	etc/dbus.conf \
	etc/hosts
ifneq ($(TARGET_ARCH),x86)
copy_from += etc/init.goldfish.sh
else
copy_from += etc/init.x86_generic.sh
endif

dont_copy := \
	etc/init.gprs-pppd \
	etc/ppp/chap-secrets \
	etc/ppp/ip-down \
	etc/ppp/ip-up

copy_to := $(addprefix $(TARGET_OUT)/,$(copy_from))
copy_from := $(addprefix $(LOCAL_PATH)/,$(copy_from))

$(copy_to) : PRIVATE_MODULE := system_etcdir
$(copy_to) : $(TARGET_OUT)/% : $(LOCAL_PATH)/% | $(ACP)
	$(transform-prebuilt-to-target)

ALL_PREBUILT += $(copy_to)


# files that live under /...

# Only copy init.rc if the target doesn't have its own.
ifneq ($(TARGET_PROVIDES_INIT_RC),true)
ifneq ($(TARGET_ARCH),x86)
file := $(TARGET_ROOT_OUT)/init.rc
$(file) : $(LOCAL_PATH)/init.rc | $(ACP)
	$(transform-prebuilt-to-target)
else #ifneq ($(TARGET_ARCH),x86)
file := $(TARGET_ROOT_OUT)/init.rc
$(file) : $(LOCAL_PATH)/init.x86.rc | $(ACP)
	$(transform-prebuilt-to-target)
endif
ALL_PREBUILT += $(file)
endif

ifneq ($(TARGET_ARCH),x86)
file := $(TARGET_ROOT_OUT)/init.goldfish.rc
$(file) : $(LOCAL_PATH)/etc/init.goldfish.rc | $(ACP)
	$(transform-prebuilt-to-target)
else #ifneq ($(TARGET_ARCH),x86)
file := $(TARGET_ROOT_OUT)/init.x86_generic.rc
$(file) : $(LOCAL_PATH)/etc/init.x86_generic.rc | $(ACP)
	$(transform-prebuilt-to-target)
endif
ALL_PREBUILT += $(file)
	

# create some directories (some are mount points)
DIRS := $(addprefix $(TARGET_ROOT_OUT)/, \
		sbin \
		dev \
		proc \
		sys \
		system \
		data \
	) \
	$(TARGET_OUT_DATA)

$(DIRS):
	@echo Directory: $@
	@mkdir -p $@

ALL_PREBUILT += $(DIRS)

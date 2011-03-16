LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

TOOLS_ALWAYS := \
	ls \
	mount \
	ps \
	ln \
	insmod \
	rmmod \
	ifconfig \
	setconsole \
	rm \
	mkdir \
	rmdir \
	reboot \
	getevent \
	sendevent \
	date \
	wipe \
	sync \
	umount \
	start \
	stop \
	notify \
	cmp \
	dmesg \
	route \
	hd \
	dd \
	df \
	getprop \
	setprop \
	watchprops \
	log \
	renice \
	printenv \
	smd \
	chmod \
	chown \
	newfs_msdos \
	netstat \
	ioctl \
	mv \
	schedtop \
	top \
	iftop \
	id \
	uptime \
	vmstat \
	nandread \
	ionice \
	lsof

# - printenv cannot be mksh "set" because "printenv foo bar" differs
# - mv cannot be mksh "rename" since it doesn't check whether the
#   destination is a directory, and does only one file
# - cat can be mksh "cat" despite not having any options, because
#   Android has never really had a "cat" command, so nothing uses it
# - lsmod just calls cat, we've just patched it as alias into mksh
TOOLS_MKSH := \
	cat \
	kill \
	lsmod \
	sleep \

ifeq ($(TARGET_SHELL),mksh)
TOOLS := $(TOOLS_ALWAYS)
else
TOOLS := $(TOOLS_ALWAYS) $(TOOLS_MKSH)
endif

LOCAL_SRC_FILES:= \
	toolbox.c \
	$(patsubst %,%.c,$(TOOLS))

LOCAL_SHARED_LIBRARIES := libcutils libc

LOCAL_MODULE:= toolbox

# Including this will define $(intermediates).
#
include $(BUILD_EXECUTABLE)

$(LOCAL_PATH)/toolbox.c: $(intermediates)/tools.h

TOOLS_H := $(intermediates)/tools.h
$(TOOLS_H): PRIVATE_TOOLS := $(TOOLS)
$(TOOLS_H): PRIVATE_CUSTOM_TOOL = echo "/* file generated automatically */" > $@ ; for t in $(PRIVATE_TOOLS) ; do echo "TOOL($$t)" >> $@ ; done
$(TOOLS_H): $(LOCAL_PATH)/Android.mk
$(TOOLS_H):
	$(transform-generated-source)

# Make #!/system/bin/toolbox launchers for each tool.
#
SYMLINKS := $(addprefix $(TARGET_OUT)/bin/,$(TOOLS))
$(SYMLINKS): TOOLBOX_BINARY := $(LOCAL_MODULE)
$(SYMLINKS): $(LOCAL_INSTALLED_MODULE) $(LOCAL_PATH)/Android.mk
	@echo "Symlink: $@ -> $(TOOLBOX_BINARY)"
	@mkdir -p $(dir $@)
	@rm -rf $@
	$(hide) ln -sf $(TOOLBOX_BINARY) $@

ifeq ($(TARGET_SHELL),mksh)
SYMLINKS_MKSH := $(addprefix $(TARGET_OUT)/bin/,$(TOOLS_MKSH))
$(SYMLINKS_MKSH): TOOLBOX_BINARY := $(TARGET_SHELL)
$(SYMLINKS_MKSH): $(LOCAL_INSTALLED_MODULE) $(LOCAL_PATH)/Android.mk
	@echo "Symlink: $@ -> $(TOOLBOX_BINARY)"
	@mkdir -p $(dir $@)
	@rm -rf $@
	$(hide) ln -sf $(TOOLBOX_BINARY) $@
endif

ALL_DEFAULT_INSTALLED_MODULES += $(SYMLINKS)

# We need this so that the installed files could be picked up based on the
# local module name
ALL_MODULES.$(LOCAL_MODULE).INSTALLED := \
    $(ALL_MODULES.$(LOCAL_MODULE).INSTALLED) $(SYMLINKS)

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
# - lsmod just calls cat, mksh has it as android specific builtin
TOOLS_notash :=
TOOLS_notmksh := \
	cat \
	kill \
	lsmod \
	sleep \

TOOLS := $(TOOLS_ALWAYS) $(TOOLS_not$(TARGET_SHELL))

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
SYMLINKS := $(addprefix $(TARGET_OUT)/bin/,$(TOOLS_ALWAYS))
$(SYMLINKS): TOOLBOX_BINARY := $(LOCAL_MODULE)
$(SYMLINKS): $(LOCAL_INSTALLED_MODULE) $(LOCAL_PATH)/Android.mk
	@echo "Symlink: $@ -> $(TOOLBOX_BINARY)"
	@mkdir -p $(dir $@)
	@rm -rf $@
	$(hide) ln -sf $(TOOLBOX_BINARY) $@

SYMLINKTARGET_ash := $(LOCAL_MODULE)
SYMLINKTARGET_mksh := mksh

SYMLINKS_MKSH := $(addprefix $(TARGET_OUT)/bin/,$(TOOLS_notmksh))
$(SYMLINKS_MKSH): TOOLBOX_BINARY := $(SYMLINKTARGET_$(TARGET_SHELL))
$(SYMLINKS_MKSH): $(LOCAL_INSTALLED_MODULE) $(LOCAL_PATH)/Android.mk
	@echo "Symlink: $@ -> $(TOOLBOX_BINARY)"
	@mkdir -p $(dir $@)
	@rm -rf $@
	$(hide) ln -sf $(TOOLBOX_BINARY) $@

ALL_DEFAULT_INSTALLED_MODULES += $(SYMLINKS) $(SYMLINKS_MKSH)

# We need this so that the installed files could be picked up based on the
# local module name
ALL_MODULES.$(LOCAL_MODULE).INSTALLED := \
    $(ALL_MODULES.$(LOCAL_MODULE).INSTALLED) $(SYMLINKS)

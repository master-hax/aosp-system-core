# Copyright © 2010
#	Thorsten Glaser <t.glaser@tarent.de>
# This file is provided under the same terms as mksh.

LOCAL_PATH:=		$(call my-dir)


# /system/etc/mkshrc

include $(CLEAR_VARS)

# if TARGET_SHELL=mksh, build and install, else, build only
ifeq ($(TARGET_SHELL),mksh)
LOCAL_MODULE_TAGS:=	user
else
LOCAL_MODULE_TAGS:=	optional
endif

LOCAL_MODULE:=		mkshrc
LOCAL_MODULE_CLASS:=	ETC
LOCAL_MODULE_PATH:=	$(TARGET_OUT)/etc
LOCAL_SRC_FILES:=	$(LOCAL_MODULE)
include $(BUILD_PREBUILT)


# /system/bin/mksh

include $(CLEAR_VARS)

# if TARGET_SHELL=mksh, build and install, otherwise build only
ifeq ($(TARGET_SHELL),mksh)
LOCAL_MODULE_TAGS:=	user
else
LOCAL_MODULE_TAGS:=	optional
endif

LOCAL_MODULE:=		mksh

# mksh source files
LOCAL_SRC_FILES:=	src/lalloc.c src/edit.c src/eval.c src/exec.c \
			src/expr.c src/funcs.c src/histrap.c src/jobs.c \
			src/lex.c src/main.c src/misc.c src/shf.c \
			src/syn.c src/tree.c src/var.c

LOCAL_SYSTEM_SHARED_LIBRARIES:= libc

LOCAL_C_INCLUDES:=	$(LOCAL_PATH)/src
# from Makefrag.inc: CFLAGS, CPPFLAGS
LOCAL_CFLAGS:=		-fno-strict-aliasing -fwrapv \
			-DMKSH_DEFAULT_EXECSHELL=\"/system/bin/sh\" \
			-DMKSH_DEFAULT_TMPDIR=\"/sqlite_stmt_journals\" \
			-DMKSHRC_PATH=\"/system/etc/mkshrc\" \
			-Wall -Wextra \
			-DMKSH_ASSUME_UTF8=0 -DMKSH_NOPWNAM \
			-D_GNU_SOURCE \
			-DHAVE_ATTRIBUTE_BOUNDED=0 -DHAVE_ATTRIBUTE_FORMAT=1 \
			-DHAVE_ATTRIBUTE_NONNULL=1 -DHAVE_ATTRIBUTE_NORETURN=1 \
			-DHAVE_ATTRIBUTE_UNUSED=1 -DHAVE_ATTRIBUTE_USED=1 \
			-DHAVE_SYS_PARAM_H=1 -DHAVE_SYS_MKDEV_H=0 \
			-DHAVE_SYS_MMAN_H=1 -DHAVE_SYS_SYSMACROS_H=1 \
			-DHAVE_LIBGEN_H=1 -DHAVE_LIBUTIL_H=0 -DHAVE_PATHS_H=1 \
			-DHAVE_STDBOOL_H=1 -DHAVE_STRINGS_H=1 -DHAVE_GRP_H=1 \
			-DHAVE_ULIMIT_H=0 -DHAVE_VALUES_H=0 -DHAVE_STDINT_H=1 \
			-DHAVE_RLIM_T=0 -DHAVE_SIG_T=1 -DHAVE_SYS_SIGNAME=1 \
			-DHAVE_SYS_SIGLIST=1 -DHAVE_STRSIGNAL=0 \
			-DHAVE_ARC4RANDOM=1 -DHAVE_ARC4RANDOM_PUSHB=0 \
			-DHAVE_GETRUSAGE=1 -DHAVE_KILLPG=0 -DHAVE_MKNOD=0 \
			-DHAVE_MKSTEMP=1 -DHAVE_NICE=1 -DHAVE_REVOKE=0 \
			-DHAVE_SETLOCALE_CTYPE=0 -DHAVE_LANGINFO_CODESET=0 \
			-DHAVE_SETMODE=1 -DHAVE_SETRESUGID=1 \
			-DHAVE_SETGROUPS=1 -DHAVE_STRCASESTR=1 \
			-DHAVE_STRLCPY=1 -DHAVE_ARC4RANDOM_DECL=1 \
			-DHAVE_ARC4RANDOM_PUSHB_DECL=1 -DHAVE_FLOCK_DECL=1 \
			-DHAVE_REVOKE_DECL=1 -DHAVE_SYS_SIGLIST_DECL=1 \
			-DHAVE_PERSISTENT_HISTORY=0

include $(BUILD_EXECUTABLE)


# only if TARGET_SHELL=mksh: symlink /system/bin/sh → mksh

ifeq ($(TARGET_SHELL),mksh)
SYMLINK := $(TARGET_OUT)/bin/sh
$(SYMLINK): LOCAL_MODULE := $(LOCAL_MODULE)
$(SYMLINK): $(LOCAL_INSTALLED_MODULE)
	@echo "Symlink: $@ -> $(LOCAL_MODULE)"
	@rm -rf $@
	$(hide) ln -sf $(LOCAL_MODULE) $@

ALL_DEFAULT_INSTALLED_MODULES += $(SYMLINK)
ALL_MODULES.$(LOCAL_MODULE).INSTALLED += $(SYMLINK)
endif

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE:= ash

# if TARGET_SHELL=ash, build and install, otherwise build only
ifeq ($(TARGET_SHELL),ash)
LOCAL_MODULE_TAGS:= user
else
LOCAL_MODULE_TAGS:= optional
endif

LOCAL_SRC_FILES:= \
	alias.c \
	arith.c \
	arith_lex.c \
	builtins.c \
	cd.c \
	error.c \
	eval.c \
	exec.c \
	expand.c \
	input.c \
	jobs.c \
	main.c \
	memalloc.c \
	miscbltin.c \
	mystring.c \
	nodes.c \
	options.c \
	parser.c \
	redir.c \
	show.c \
	syntax.c \
	trap.c \
	output.c \
	var.c \
	bltin/echo.c \
	init.c

LOCAL_CFLAGS += -DSHELL -DWITH_LINENOISE

LOCAL_STATIC_LIBRARIES := liblinenoise

LOCAL_C_INCLUDES += system/core/liblinenoise

make_ash_files: PRIVATE_SRC_FILES := $(SRC_FILES)
make_ash_files: PRIVATE_CFLAGS := $(LOCAL_CFLAGS)
make_ash_files:
	p4 edit arith.c arith_lex.c arith.h builtins.h builtins.c 
	p4 edit init.c nodes.c nodes.h token.h 
	sh ./mktokens
	bison -o arith.c arith.y
	flex -o arith_lex.c arith_lex.l
	perl -ne 'print if ( /^\#\s*define\s+ARITH/ );' < arith.c > arith.h
	sh ./mkbuiltins shell.h builtins.def . -Wall -O2
	sh ./mknodes.sh nodetypes nodes.c.pat .
	sh ./mkinit.sh $(PRIVATE_SRC_FILES) 

include $(BUILD_EXECUTABLE)


# only if TARGET_SHELL=ash: symlink /system/bin/sh → ash

ifeq ($(TARGET_SHELL),ash)
SYMLINK := $(TARGET_OUT)/bin/sh
$(SYMLINK): LOCAL_MODULE := $(LOCAL_MODULE)
$(SYMLINK): $(LOCAL_INSTALLED_MODULE)
	@echo "Symlink: $@ -> $(LOCAL_MODULE)"
	@rm -rf $@
	$(hide) ln -sf $(LOCAL_MODULE) $@

ALL_DEFAULT_INSTALLED_MODULES += $(SYMLINK)
ALL_MODULES.$(LOCAL_MODULE).INSTALLED += $(SYMLINK)
endif

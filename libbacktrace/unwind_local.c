/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "libbacktrace"

#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <cutils/log.h>
#include <backtrace/backtrace.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <libunwind-ptrace.h>

#include "common.h"
#include "demangle.h"
#include "thread.h"

static bool local_get_frames(backtrace_t* backtrace) {
  unw_context_t* context = (unw_context_t*)backtrace->private_data;

  int ret = unw_getcontext(context);
  if (ret < 0) {
    ALOGW("%s::%s(): unw_getcontext failed %d\n", __FILE__, __FUNCTION__, ret);
    return false;
  }

  // The cursor structure is quite large, do not let it sit on the stack.
  unw_cursor_t* cursor = (unw_cursor_t*)malloc(sizeof(unw_cursor_t));
  if (cursor == NULL) {
    ALOGW("%s::%s(): Cannot allocate cursor structure.\n", __FILE__,
          __FUNCTION__);
    return false;
  }
  ret = unw_init_local(cursor, context);
  if (ret < 0) {
    ALOGW("%s::%s(): unw_init_local failed %d\n", __FILE__, __FUNCTION__, ret);
    free(cursor);
    return false;
  }

  backtrace_frame_data_t* frame;
  bool returnValue = true;
  backtrace->num_frames = 0;
  uintptr_t map_start;
  unw_word_t value;
  do {
    frame = &backtrace->frames[backtrace->num_frames];
    frame->stack_size = 0;
    frame->map_name = NULL;
    frame->map_offset = 0;
    frame->proc_name = NULL;
    frame->proc_offset = 0;

    ret = unw_get_reg(cursor, UNW_REG_IP, &value);
    if (ret < 0) {
      ALOGW("%s::%s(): Failed to read IP %d\n", __FILE__, __FUNCTION__, ret);
      returnValue = false;
      break;
    }
    frame->pc = (uintptr_t)value;
    ret = unw_get_reg(cursor, UNW_REG_SP, &value);
    if (ret < 0) {
      ALOGW("%s::%s(): Failed to read IP %d\n", __FILE__, __FUNCTION__, ret);
      returnValue = false;
      break;
    }
    frame->sp = (uintptr_t)value;

    if (backtrace->num_frames) {
      backtrace_frame_data_t* prev = &backtrace->frames[backtrace->num_frames-1];
      prev->stack_size = frame->sp - prev->sp;
    }

    frame->proc_name = backtrace_get_proc_name(backtrace, frame->pc, &frame->proc_offset);

    frame->map_name = backtrace_get_map_info(backtrace, frame->pc, &map_start);
    if (frame->map_name) {
      frame->map_offset = frame->pc - map_start;
    }

    backtrace->num_frames++;
    ret = unw_step (cursor);
  } while (ret > 0 && backtrace->num_frames < MAX_BACKTRACE_FRAMES);

  free(cursor);
  return returnValue;
}

bool local_get_data(backtrace_t* backtrace) {
  unw_context_t* context = (unw_context_t*)malloc(sizeof(unw_context_t));
  backtrace->private_data = context;

  if (!local_get_frames(backtrace)) {
    backtrace_free_data(backtrace);
    return false;
  }

  return true;
}

void local_free_data(backtrace_t* backtrace) {
  if (backtrace->private_data) {
    free(backtrace->private_data);
    backtrace->private_data = NULL;
  }
}

char* local_get_proc_name(const backtrace_t* backtrace, uintptr_t pc,
                          uintptr_t* offset) {
  unw_context_t* context = (unw_context_t*)backtrace->private_data;
  char buf[512];

  *offset = 0;
  unw_word_t value;
  if (unw_get_proc_name_by_ip(unw_local_addr_space, pc, buf, sizeof(buf),
                              &value, context) >= 0 && buf[0] != '\0') {
    *offset = (uintptr_t)value;
    char* symbol = demangle_symbol_name(buf);
    if (!symbol) {
      symbol = strdup(buf);
    }
    return symbol;
  }
  return NULL;
}

void gather_thread_frame_data(tid_list_t*entry, siginfo_t* siginfo,
                              void* sigcontext) {
  unw_context_t* unw_context = (unw_context_t*)malloc(sizeof(unw_context_t));
  entry->backtrace->private_data = unw_context;
  unw_tdep_context_t* context = (unw_tdep_context_t*)unw_context;

#if defined(__arm__)
  #if !defined(__BIONIC_HAVE_UCONTEXT_T)
  /* Old versions of the Android <signal.h> didn't define ucontext_t. */
  #include <asm/sigcontext.h> /* Ensure 'struct sigcontext' is defined. */

  /* Machine context at the time a signal was raised. */
  typedef struct ucontext {
    uint32_t uc_flags;
    struct ucontext* uc_link;
    stack_t uc_stack;
    struct sigcontext uc_mcontext;
    uint32_t uc_sigmask;
  } ucontext_t;
  #endif /* !__BIONIC_HAVE_UCONTEXT_T */

  const ucontext_t* uc = (const ucontext_t*)sigcontext;

  context->regs[0] = uc->uc_mcontext.arm_r0;
  context->regs[1] = uc->uc_mcontext.arm_r1;
  context->regs[2] = uc->uc_mcontext.arm_r2;
  context->regs[3] = uc->uc_mcontext.arm_r3;
  context->regs[4] = uc->uc_mcontext.arm_r4;
  context->regs[5] = uc->uc_mcontext.arm_r5;
  context->regs[6] = uc->uc_mcontext.arm_r6;
  context->regs[7] = uc->uc_mcontext.arm_r7;
  context->regs[8] = uc->uc_mcontext.arm_r8;
  context->regs[9] = uc->uc_mcontext.arm_r9;
  context->regs[10] = uc->uc_mcontext.arm_r10;
  context->regs[11] = uc->uc_mcontext.arm_fp;
  context->regs[12] = uc->uc_mcontext.arm_ip;
  context->regs[13] = uc->uc_mcontext.arm_sp;
  context->regs[14] = uc->uc_mcontext.arm_lr;
  context->regs[15] = uc->uc_mcontext.arm_pc;

#elif defined(__mips__)

  typedef struct ucontext {
    uint32_t sp;
    uint32_t ra;
    uint32_t pc;
  } ucontext_t;

  const ucontext_t* uc = (const ucontext_t*)sigcontext;

  context->uc_mcontext.sp = uc->sp;
  context->uc_mcontext.pc = uc->pc;
  context->uc_mcontext.ra = uc->ra;

#elif defined(__x86__)

  #include <asm/sigcontext.h>
  #include <asm/ucontext.h>
  typedef struct ucontext ucontext_t;

  const ucontext_t* uc = (const ucontext_t*)sigcontext;

  uc->uc_mcontext.gregs[REG_EBP] = uc->uc_mcontext.gregs[REG_EBP];
  uc->uc_mcontext.gregs[REG_ESP] = uc->uc_mcontext.gregs[REG_ESP];
  uc->uc_mcontext.gregs[REG_EIP] = uc->uc_mcontext.gregs[REG_EIP];

#endif

  // The cursor structure is quite large, do not let it sit on the stack.
  unw_cursor_t* cursor = (unw_cursor_t*)malloc(sizeof(unw_cursor_t));
  if (cursor == NULL) {
    ALOGW("%s::%s(): Cannot allocate cursor structure.\n", __FILE__,
          __FUNCTION__);
    return;
  }
  int ret = unw_init_local(cursor, unw_context);
  if (ret < 0) {
    ALOGW("%s::%s(): unw_init_local failed %d\n", __FILE__, __FUNCTION__, ret);
    free(cursor);
    return;
  }

  backtrace_frame_data_t* frame;
  backtrace_t* backtrace = entry->backtrace;
  backtrace->num_frames = 0;
  unw_word_t value;
  do {
    frame = &backtrace->frames[backtrace->num_frames];
    frame->stack_size = 0;
    frame->map_name = NULL;
    frame->map_offset = 0;
    frame->proc_name = NULL;
    frame->proc_offset = 0;

    ret = unw_get_reg(cursor, UNW_REG_IP, &value);
    if (ret < 0) {
      ALOGW("%s::%s(): Failed to read IP %d\n", __FILE__, __FUNCTION__, ret);
      break;
    }
    frame->pc = (uintptr_t)value;
    ret = unw_get_reg(cursor, UNW_REG_SP, &value);
    if (ret < 0) {
      ALOGW("%s::%s(): Failed to read IP %d\n", __FILE__, __FUNCTION__, ret);
      break;
    }
    frame->sp = (uintptr_t)value;

    if (backtrace->num_frames) {
      backtrace_frame_data_t* prev = &backtrace->frames[backtrace->num_frames-1];
      prev->stack_size = frame->sp - prev->sp;
    }

    backtrace->num_frames++;
    ret = unw_step (cursor);
  } while (ret > 0 && backtrace->num_frames < MAX_BACKTRACE_FRAMES);
  free(cursor);
}

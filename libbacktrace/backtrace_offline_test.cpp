#include <libunwind.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <backtrace/Backtrace.h>
#include <backtrace/BacktraceMap.h>

#include <gtest/gtest.h>

bool exit_flag = false;

static void GetContextAndExit(void* arg) {
  unw_context_t* unw_context = reinterpret_cast<unw_context_t*>(arg);
  unw_getcontext(unw_context);
  // Don't touch the stack anymore.
  while (!exit_flag) {
  }
}

struct OfflineThreadFnArg {
  unw_context_t unw_context;
  pid_t tid;
};

extern "C" pid_t gettid();

extern "C" {
// Prototypes for functions in the test library.
int test_level_one(int, int, int, int, void (*)(void*), void*);
int test_level_two(int, int, int, int, void (*)(void*), void*);
int test_level_three(int, int, int, int, void (*)(void*), void*);
int test_level_four(int, int, int, int, void (*)(void*), void*);
int test_recursive_call(int, int, int, int, void (*)(void*), void*);
}

static void* OfflineThreadFn(void* arg) {
  OfflineThreadFnArg* fn_arg = reinterpret_cast<OfflineThreadFnArg*>(arg);
  fn_arg->tid = gettid();
  test_level_one(1, 2, 3, 4, GetContextAndExit, &fn_arg->unw_context);
  return nullptr;
}

struct Symbol {
  std::string name;
  uintptr_t start;
  uintptr_t end;
};

static std::string PcToSymbolName(uintptr_t pc, const std::vector<Symbol>& symbols) {
  for (auto& symbol : symbols) {
    if (pc >= symbol.start && pc < symbol.end) {
      return symbol.name;
    }
  }
  return "";
}

class NotifyThreadOnExit {
 public:
  ~NotifyThreadOnExit() {
    exit_flag = true;
  }
};

static ucontext_t GetUContextFromUnwContext(const unw_context_t& unw_context) {
  ucontext_t ucontext;
  memset(&ucontext, 0, sizeof(ucontext));
#if defined(__arm__)
  ucontext.uc_mcontext.arm_r0 = unw_context.regs[0];
  ucontext.uc_mcontext.arm_r1 = unw_context.regs[1];
  ucontext.uc_mcontext.arm_r2 = unw_context.regs[2];
  ucontext.uc_mcontext.arm_r3 = unw_context.regs[3];
  ucontext.uc_mcontext.arm_r4 = unw_context.regs[4];
  ucontext.uc_mcontext.arm_r5 = unw_context.regs[5];
  ucontext.uc_mcontext.arm_r6 = unw_context.regs[6];
  ucontext.uc_mcontext.arm_r7 = unw_context.regs[7];
  ucontext.uc_mcontext.arm_r8 = unw_context.regs[8];
  ucontext.uc_mcontext.arm_r9 = unw_context.regs[9];
  ucontext.uc_mcontext.arm_r10 = unw_context.regs[10];
  ucontext.uc_mcontext.arm_fp = unw_context.regs[11];
  ucontext.uc_mcontext.arm_ip = unw_context.regs[12];
  ucontext.uc_mcontext.arm_sp = unw_context.regs[13];
  ucontext.uc_mcontext.arm_lr = unw_context.regs[14];
  ucontext.uc_mcontext.arm_pc = unw_context.regs[15];
#else
  ucontext.uc_mcontext = unw_context.uc_mcontext;
#endif
  return ucontext;
}

TEST(libbacktrace, offline) {
  std::vector<uint8_t> stack(PTHREAD_STACK_MIN * 2);
  uintptr_t stack_begin = reinterpret_cast<uintptr_t>(stack.data());
  const size_t page_size = static_cast<size_t>(sysconf(_SC_PAGE_SIZE));
  stack_begin = (stack_begin + page_size) & ~(page_size - 1);
  uintptr_t stack_end = reinterpret_cast<uintptr_t>(stack.data() + stack.size());
  stack_end = stack_end & ~(page_size - 1);
  ASSERT_GE(stack_end, stack_begin + PTHREAD_STACK_MIN);

  pthread_attr_t attr;
  ASSERT_EQ(0, pthread_attr_init(&attr));
  ASSERT_EQ(0, pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED));
  ASSERT_EQ(0, pthread_attr_setstack(&attr, reinterpret_cast<void*>(stack_begin),
                                     stack_end - stack_begin));
  pthread_t thread;
  OfflineThreadFnArg fn_arg;
  ASSERT_EQ(0, pthread_create(&thread, &attr, OfflineThreadFn, &fn_arg));
  sleep(1);
  NotifyThreadOnExit notifier;

  std::unique_ptr<BacktraceMap> map(BacktraceMap::Create(getpid()));
  ASSERT_TRUE(map != nullptr);

  StackInfo stack_info;
  stack_info.stack_addr = reinterpret_cast<uintptr_t>(stack.data());
  stack_info.stack_size = stack.size();
  stack_info.stack_data = stack.data();

  std::unique_ptr<Backtrace> backtrace(
      Backtrace::CreateOffline(getpid(), fn_arg.tid, map.get(), stack_info));
  ASSERT_TRUE(backtrace != nullptr);

  ucontext_t ucontext = GetUContextFromUnwContext(fn_arg.unw_context);
  ASSERT_TRUE(backtrace->Unwind(0, &ucontext));

  std::vector<Symbol> symbols = {
      {"unknown_start", 0, 0},
      {"test_level_one", reinterpret_cast<uintptr_t>(&test_level_one), 0},
      {"test_level_two", reinterpret_cast<uintptr_t>(&test_level_two), 0},
      {"test_level_three", reinterpret_cast<uintptr_t>(&test_level_three), 0},
      {"test_level_four", reinterpret_cast<uintptr_t>(&test_level_four), 0},
      {"test_recursive_call", reinterpret_cast<uintptr_t>(&test_recursive_call), 0},
      {"GetContextAndExit", reinterpret_cast<uintptr_t>(&GetContextAndExit), 0},
      {"unknown_end", static_cast<uintptr_t>(-1), static_cast<uintptr_t>(-1)},
  };
  std::sort(symbols.begin(), symbols.end(),
            [](const Symbol& s1, const Symbol& s2) { return s1.start < s2.start; });
  for (size_t i = 0; i + 1 < symbols.size(); ++i) {
    symbols[i].end = symbols[i + 1].start;
  }

  ASSERT_GT(backtrace->NumFrames(), 0u);
  ASSERT_LT(backtrace->NumFrames(), static_cast<size_t>(MAX_BACKTRACE_FRAMES));

  size_t frame_index = 0;
  for (size_t i = backtrace->NumFrames() - 1; i > 2; --i) {
    if (PcToSymbolName(backtrace->GetFrame(i)->pc, symbols) == "test_level_one") {
      frame_index = i;
      break;
    }
  }

  ASSERT_GE(frame_index, 3u);
  ASSERT_EQ(PcToSymbolName(backtrace->GetFrame(frame_index)->pc, symbols), "test_level_one");
  ASSERT_EQ(PcToSymbolName(backtrace->GetFrame(frame_index - 1)->pc, symbols), "test_level_two");
  ASSERT_EQ(PcToSymbolName(backtrace->GetFrame(frame_index - 2)->pc, symbols), "test_level_three");
  ASSERT_EQ(PcToSymbolName(backtrace->GetFrame(frame_index - 3)->pc, symbols), "test_level_four");
}

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

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"

#include <llvm/ADT/StringRef.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/ObjectFile.h>

#pragma clang diagnostic pop

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

using DebugFrameInfo = BacktraceOfflineCallbacks::DebugFrameInfo;

template <class ELFT>
bool FillDebugFrameInfo(const llvm::object::ELFFile<ELFT>* elf, DebugFrameInfo* debug_frame) {
  bool has_eh_frame_hdr = false;
  bool has_eh_frame = false;
  bool has_debug_frame = false;
  for (auto it = elf->begin_sections(); it != elf->end_sections(); ++it) {
    llvm::ErrorOr<llvm::StringRef> name = elf->getSectionName(&*it);
    llvm::ErrorOr<llvm::ArrayRef<uint8_t>> data = elf->getSectionContents(&*it);
    if (name && data) {
      if (name.get() == ".eh_frame_hdr") {
        has_eh_frame_hdr = true;
        debug_frame->eh_frame.eh_frame_hdr_vaddr = it->sh_addr;
        debug_frame->eh_frame.eh_frame_hdr_data =
            std::vector<uint8_t>(data->data(), data->data() + data->size());
      } else if (name.get() == ".eh_frame") {
        has_eh_frame = true;
        debug_frame->eh_frame.eh_frame_vaddr = it->sh_addr;
        debug_frame->eh_frame.eh_frame_data =
            std::vector<uint8_t>(data->data(), data->data() + data->size());
      } else if (name.get() == ".debug_frame") {
        has_debug_frame = true;
      }
    }
  }
  if (!(has_eh_frame_hdr && has_eh_frame) && !(has_debug_frame)) {
    return false;
  }
  if (has_eh_frame_hdr && has_eh_frame) {
    debug_frame->is_eh_frame = true;
    debug_frame->eh_frame.fde_table_offset_in_eh_frame_hdr = 0;
    debug_frame->eh_frame.program_headers.clear();
    for (auto it = elf->begin_program_headers(); it != elf->end_program_headers(); ++it) {
      DebugFrameInfo::EhFrame::ProgramHeader header;
      header.vaddr = it->p_vaddr;
      header.file_offset = it->p_offset;
      header.file_size = it->p_filesz;
      debug_frame->eh_frame.program_headers.push_back(header);
    }
  }
  return true;
}

static DebugFrameInfo* GetDebugFrameInfo(const std::string& filename) {
  static DebugFrameInfo debug_frame;

  auto owning_binary = llvm::object::createBinary(llvm::StringRef(filename));
  if (owning_binary.getError()) {
    return nullptr;
  }
  llvm::object::Binary* binary = owning_binary.get().getBinary();
  auto obj = llvm::dyn_cast<llvm::object::ObjectFile>(binary);
  if (obj == nullptr) {
    return nullptr;
  }
  if (auto elf = llvm::dyn_cast<llvm::object::ELF32LEObjectFile>(obj)) {
    if (!FillDebugFrameInfo(elf->getELFFile(), &debug_frame)) {
      return nullptr;
    }
  } else if (auto elf = llvm::dyn_cast<llvm::object::ELF64LEObjectFile>(obj)) {
    if (!FillDebugFrameInfo(elf->getELFFile(), &debug_frame)) {
      return nullptr;
    }
  }
  return &debug_frame;
}

static size_t ReadStack(const std::vector<uint8_t>& stack, uint64_t addr, uint8_t* buffer,
                        size_t size) {
  if (addr >= reinterpret_cast<uintptr_t>(stack.data()) &&
      addr < reinterpret_cast<uintptr_t>(stack.data() + stack.size())) {
    size_t offset = addr - reinterpret_cast<uintptr_t>(stack.data());
    size_t read_size = std::min((stack.size() - offset), size);
    memcpy(buffer, stack.data() + offset, read_size);
    return read_size;
  }
  return 0;
}

static bool ReadReg(const unw_context_t& unw_context, size_t reg_index, uint64_t* reg_value) {
#if defined(__arm__)
  if (reg_index < 16) {
    *reg_value = unw_context.regs[reg_index];
    return true;
  }
#elif defined(__aarch64__)
  if (reg_index < 32) {
    *reg_value = unw_context.uc_mcontext.regs[reg_index];
    return true;
  }
#elif defined(__i386__)
  switch (reg_index) {
    case UNW_X86_GS:
      *reg_value = unw_context.uc_mcontext.gregs[REG_GS];
      break;
    case UNW_X86_FS:
      *reg_value = unw_context.uc_mcontext.gregs[REG_FS];
      break;
    case UNW_X86_ES:
      *reg_value = unw_context.uc_mcontext.gregs[REG_ES];
      break;
    case UNW_X86_DS:
      *reg_value = unw_context.uc_mcontext.gregs[REG_DS];
      break;
    case UNW_X86_EAX:
      *reg_value = unw_context.uc_mcontext.gregs[REG_EAX];
      break;
    case UNW_X86_EBX:
      *reg_value = unw_context.uc_mcontext.gregs[REG_EBX];
      break;
    case UNW_X86_ECX:
      *reg_value = unw_context.uc_mcontext.gregs[REG_ECX];
      break;
    case UNW_X86_EDX:
      *reg_value = unw_context.uc_mcontext.gregs[REG_EDX];
      break;
    case UNW_X86_ESI:
      *reg_value = unw_context.uc_mcontext.gregs[REG_ESI];
      break;
    case UNW_X86_EDI:
      *reg_value = unw_context.uc_mcontext.gregs[REG_EDI];
      break;
    case UNW_X86_EBP:
      *reg_value = unw_context.uc_mcontext.gregs[REG_EBP];
      break;
    case UNW_X86_EIP:
      *reg_value = unw_context.uc_mcontext.gregs[REG_EIP];
      break;
    case UNW_X86_ESP:
      *reg_value = unw_context.uc_mcontext.gregs[REG_ESP];
      break;
    case UNW_X86_TRAPNO:
      *reg_value = unw_context.uc_mcontext.gregs[REG_TRAPNO];
      break;
    case UNW_X86_CS:
      *reg_value = unw_context.uc_mcontext.gregs[REG_CS];
      break;
    case UNW_X86_EFLAGS:
      *reg_value = unw_context.uc_mcontext.gregs[REG_EFL];
      break;
    case UNW_X86_SS:
      *reg_value = unw_context.uc_mcontext.gregs[REG_SS];
      break;
    default:
      return false;
  }
  return true;
#elif defined(__x86_64__)
  switch (reg_index) {
    case UNW_X86_64_R8:
      *reg_value = unw_context.uc_mcontext.gregs[REG_R8];
      break;
    case UNW_X86_64_R9:
      *reg_value = unw_context.uc_mcontext.gregs[REG_R9];
      break;
    case UNW_X86_64_R10:
      *reg_value = unw_context.uc_mcontext.gregs[REG_R10];
      break;
    case UNW_X86_64_R11:
      *reg_value = unw_context.uc_mcontext.gregs[REG_R11];
      break;
    case UNW_X86_64_R12:
      *reg_value = unw_context.uc_mcontext.gregs[REG_R12];
      break;
    case UNW_X86_64_R13:
      *reg_value = unw_context.uc_mcontext.gregs[REG_R13];
      break;
    case UNW_X86_64_R14:
      *reg_value = unw_context.uc_mcontext.gregs[REG_R14];
      break;
    case UNW_X86_64_R15:
      *reg_value = unw_context.uc_mcontext.gregs[REG_R15];
      break;
    case UNW_X86_64_RDI:
      *reg_value = unw_context.uc_mcontext.gregs[REG_RDI];
      break;
    case UNW_X86_64_RSI:
      *reg_value = unw_context.uc_mcontext.gregs[REG_RSI];
      break;
    case UNW_X86_64_RBP:
      *reg_value = unw_context.uc_mcontext.gregs[REG_RBP];
      break;
    case UNW_X86_64_RBX:
      *reg_value = unw_context.uc_mcontext.gregs[REG_RBX];
      break;
    case UNW_X86_64_RDX:
      *reg_value = unw_context.uc_mcontext.gregs[REG_RDX];
      break;
    case UNW_X86_64_RAX:
      *reg_value = unw_context.uc_mcontext.gregs[REG_RAX];
      break;
    case UNW_X86_64_RCX:
      *reg_value = unw_context.uc_mcontext.gregs[REG_RCX];
      break;
    case UNW_X86_64_RSP:
      *reg_value = unw_context.uc_mcontext.gregs[REG_RSP];
      break;
    case UNW_X86_64_RIP:
      *reg_value = unw_context.uc_mcontext.gregs[REG_RIP];
      break;
    default:
      return false;
  }
  return true;
#elif defined(__mips__)
  if (reg_index >= UNW_MIPS_R0 && reg < UNW_MIPS_R0 + 32) {
    *reg_value = unw_context.uc_mcontext.gregs[reg_index - UNW_MIPS_R0];
    return true;
  } else if (reg_index == UNW_MIPS_PC) {
    *reg_value = unw_context.uc_mcontext.pc;
    return true;
  }
#endif
  return false;
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

  BacktraceOfflineCallbacks callbacks;
  callbacks.GetDebugFrameInfo = GetDebugFrameInfo;
  callbacks.ReadStack = std::bind(ReadStack, std::ref(stack), std::placeholders::_1,
                                  std::placeholders::_2, std::placeholders::_3);
  callbacks.ReadReg = std::bind(ReadReg, std::ref(fn_arg.unw_context), std::placeholders::_1,
                                std::placeholders::_2);

  std::unique_ptr<Backtrace> backtrace(
      Backtrace::CreateOffline(getpid(), fn_arg.tid, map.get(), callbacks));
  ASSERT_TRUE(backtrace != nullptr);

  ASSERT_TRUE(backtrace->Unwind(0));

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

  ASSERT_GT(frame_index, 3u);
  ASSERT_EQ(PcToSymbolName(backtrace->GetFrame(frame_index)->pc, symbols), "test_level_one");
  ASSERT_EQ(PcToSymbolName(backtrace->GetFrame(frame_index - 1)->pc, symbols), "test_level_two");
  ASSERT_EQ(PcToSymbolName(backtrace->GetFrame(frame_index - 2)->pc, symbols), "test_level_three");
  ASSERT_EQ(PcToSymbolName(backtrace->GetFrame(frame_index - 3)->pc, symbols), "test_level_four");
}

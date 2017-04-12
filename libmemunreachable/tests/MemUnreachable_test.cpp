/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>

#include <sstream>
#include <string>

#include <gtest/gtest.h>

#include <memunreachable/memunreachable.h>

static void Ref(void* ptr) {
  write(0, ptr, 0);
}

class MemUnreachableTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Clear the stack between tests just in case a pointer winds up on
    // the stack and causes weird failures.
    char buffer[8192];
    memset(buffer, 0, sizeof(buffer));
    Ref(buffer);
  }
};

void* g_ptr;

class HiddenPointer {
 public:
  explicit HiddenPointer(size_t size = 256) {
    Set(malloc(size));
  }
  ~HiddenPointer() {
    Free();
  }
  void* Get() {
    return reinterpret_cast<void*>(~ptr_);
  }
  void Free() {
    free(Get());
    Set(nullptr);
  }
 private:
  void Set(void* ptr) {
    ptr_ = ~reinterpret_cast<uintptr_t>(ptr);
  }
  volatile uintptr_t ptr_;
};

static std::string MapsToString() {
  std::string map_str;
  int fd = TEMP_FAILURE_RETRY(open("/proc/self/maps", O_RDONLY | O_CLOEXEC));
  if (fd != -1) {
    char buffer[1025];
    while (true) {
      ssize_t length = TEMP_FAILURE_RETRY(read(fd, buffer, sizeof(buffer) - 1));
      if (length <= 0) {
        break;
      }
      buffer[length] = '\0';
      map_str += buffer;
    }
    close(fd);
  }
  return map_str;
}

static std::string InfoToString(const UnreachableMemoryInfo& info) {
  std::string info_str;

  info_str += "Info Dump:\n";
  info_str += "  num_leaks " + std::to_string(info.num_leaks) + '\n';
  info_str += "  leak_bytes " + std::to_string(info.leak_bytes) + '\n';
  info_str += "  num_allocations " + std::to_string(info.num_allocations) + '\n';
  info_str += "  allocation_bytes " + std::to_string(info.allocation_bytes) + "\n\n";
  for (const auto leak : info.leaks) {
    info_str += leak.ToString(true);
  }
  return info_str;
}

static std::string ErrorToString(void** value, const UnreachableMemoryInfo& info) {
  std::string error_str;

  if (value != nullptr) {
    std::stringstream stream;
    stream << std::hex << value;
    error_str += "  Address of value " + stream.str() + '\n';
    stream.str(std::string());
    stream.clear();
    stream << std::hex << *value;
    error_str += "  value " + stream.str() + '\n';
  }
  error_str += MapsToString();
  error_str += InfoToString(info);
  return error_str;
}

static void FindLeakedPointer(void** pointer, bool expect_leaked,
                              const UnreachableMemoryInfo& info) {
  // Make sure that our hidden pointer can be found in the list of leaks.
  void* value = *pointer;
  bool found = false;
  for (const auto leak : info.leaks) {
    if (leak.begin == reinterpret_cast<uintptr_t>(value)) {
      found = true;
      break;
    }
  }
  if (expect_leaked) {
    ASSERT_TRUE(found) << "Expected pointer " << std::hex << value << " to be leaked.\n"
                       << ErrorToString(pointer, info);
  } else {
    ASSERT_FALSE(found) << "Pointer " << std::hex << value
                        << " has been leaked, this is not expected.\n"
                        << ErrorToString(pointer, info);
  }
}

static void ExpectPointerLeaked(void** pointer, const UnreachableMemoryInfo& info) {
  FindLeakedPointer(pointer, true, info);
}

static void ExpectPointerNotLeaked(void** pointer, const UnreachableMemoryInfo& info) {
  FindLeakedPointer(pointer, false, info);
}

TEST_F(MemUnreachableTest, clean) {
  UnreachableMemoryInfo info;

  ASSERT_TRUE(LogUnreachableMemory(true, 100));

  ASSERT_TRUE(GetUnreachableMemory(info));
  ASSERT_EQ(0U, info.leaks.size()) << ErrorToString(nullptr, info);
}

TEST_F(MemUnreachableTest, stack) {
  // Do not use hidden pointer to try and avoid any chance the pointer
  // winds up on the stack.
  g_ptr = malloc(256);
  ASSERT_TRUE(g_ptr != nullptr);

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info, 1000, MEMUNREACHABLE_FLAG_STACK_ONLY));
    ExpectPointerLeaked(&g_ptr, info);
  }

  {
    void* ptr = g_ptr;
    g_ptr = nullptr;
    Ref(ptr);

    UnreachableMemoryInfo info;

    // Only look on the stack for these pointers.
    ASSERT_TRUE(GetUnreachableMemory(info, 1000, MEMUNREACHABLE_FLAG_STACK_ONLY));
    ExpectPointerNotLeaked(&ptr, info);

    // Need to clear out the value since nothing below guarantees that
    // something will overwrite the stack value.
    g_ptr = ptr;
    ptr = nullptr;
    Ref(ptr);
  }

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info, 1000, MEMUNREACHABLE_FLAG_STACK_ONLY));
    ExpectPointerLeaked(&g_ptr, info);
  }

  free(g_ptr);
  g_ptr = nullptr;
}

TEST_F(MemUnreachableTest, global) {
  HiddenPointer hidden_ptr;

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info, 1000, MEMUNREACHABLE_FLAG_GLOBAL_ONLY));
    void* ptr = hidden_ptr.Get();
    ExpectPointerLeaked(&ptr, info);
  }

  g_ptr = hidden_ptr.Get();

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info, 1000, MEMUNREACHABLE_FLAG_GLOBAL_ONLY));
    ExpectPointerNotLeaked(&g_ptr, info);
  }

  g_ptr = nullptr;

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info, 1000, MEMUNREACHABLE_FLAG_GLOBAL_ONLY));
    void* ptr = hidden_ptr.Get();
    ExpectPointerLeaked(&ptr, info);
  }
}

TEST_F(MemUnreachableTest, static_function_variable) {
  HiddenPointer hidden_ptr;

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info, 1000, MEMUNREACHABLE_FLAG_GLOBAL_ONLY));
    void* ptr = hidden_ptr.Get();
    ExpectPointerLeaked(&ptr, info);
  }

  static void* static_ptr = nullptr;
  static_ptr = hidden_ptr.Get();
  ASSERT_NE(nullptr, static_ptr);

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info, 1000, MEMUNREACHABLE_FLAG_GLOBAL_ONLY));
    ExpectPointerNotLeaked(&static_ptr, info);
  }

  static_ptr = nullptr;
  ASSERT_EQ(nullptr, static_ptr);

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info, 1000, MEMUNREACHABLE_FLAG_GLOBAL_ONLY));
    void* ptr = hidden_ptr.Get();
    ExpectPointerLeaked(&ptr, info);
  }
}

TEST_F(MemUnreachableTest, tls) {
  HiddenPointer hidden_ptr;
  pthread_key_t key;
  ASSERT_EQ(0, pthread_key_create(&key, nullptr));

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info, 1000, MEMUNREACHABLE_FLAG_KEYS_ONLY));
    void* pointer = hidden_ptr.Get();
    ExpectPointerLeaked(&pointer, info);
  }

  ASSERT_EQ(0, pthread_setspecific(key, hidden_ptr.Get()));

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info, 1000, MEMUNREACHABLE_FLAG_KEYS_ONLY));
    void* pointer = hidden_ptr.Get();
    ExpectPointerNotLeaked(&pointer, info);
  }

  ASSERT_EQ(0, pthread_setspecific(key, nullptr));

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info, 1000, MEMUNREACHABLE_FLAG_KEYS_ONLY));
    void* pointer = hidden_ptr.Get();
    ExpectPointerLeaked(&pointer, info);
  }

  ASSERT_EQ(0, pthread_key_delete(key));
}

TEST_F(MemUnreachableTest, twice) {
  HiddenPointer hidden_ptr;

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(1U, info.leaks.size()) << ErrorToString(nullptr, info);
  }

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(1U, info.leaks.size()) << ErrorToString(nullptr, info);
  }

  hidden_ptr.Free();

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(0U, info.leaks.size()) << ErrorToString(nullptr, info);
  }
}

TEST_F(MemUnreachableTest, log) {
  HiddenPointer hidden_ptr;

  ASSERT_TRUE(LogUnreachableMemory(true, 100));

  hidden_ptr.Free();

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(0U, info.leaks.size()) << ErrorToString(nullptr, info);
  }
}

TEST_F(MemUnreachableTest, notdumpable) {
  ASSERT_EQ(0, prctl(PR_SET_DUMPABLE, 0));

  HiddenPointer hidden_ptr;

  ASSERT_TRUE(LogUnreachableMemory(true, 100));

  ASSERT_EQ(0, prctl(PR_SET_DUMPABLE, 1));
}

TEST_F(MemUnreachableTest, leak_lots) {
  std::vector<HiddenPointer> hidden_ptrs;
  hidden_ptrs.resize(1024);

  ASSERT_TRUE(LogUnreachableMemory(true, 100));
}

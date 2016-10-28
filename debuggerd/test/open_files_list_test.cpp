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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>

#include <gtest/gtest.h>

#include "open_files_list.h"

// Check that we can produce a list of open files for the current process, and
// that it includes a known open file.
TEST(OpenFilesListTest, BasicTest) {
  // Open an file.
  char tmp_file[256];
  const char data_template[] = "/data/local/tmp/debuggerd_open_files_list_testXXXXXX";
  memcpy(tmp_file, data_template, sizeof(data_template));
  int fd = mkstemp(tmp_file);
  if (fd == -1) {
    const char tmp_template[] = "/tmp/debuggerd_open_files_list_testXXXXXX";
    memcpy(tmp_file, tmp_template, sizeof(tmp_template));
    fd = mkstemp(tmp_file);
    ASSERT_NE(-1, fd) << tmp_file;
  }

  // Get the list of open files for this process.
  OpenFilesList list;
  populate_open_files_list(getpid(), &list);

  // Verify our open file is in the list.
  bool found = false;
  for (auto&  file : list) {
    if (file.first == fd) {
      EXPECT_EQ(file.second, std::string(tmp_file));
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found);
  
  close(fd);
}

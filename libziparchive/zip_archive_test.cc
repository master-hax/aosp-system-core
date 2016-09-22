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

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if !defined(_WIN32)
#include <pthread.h>
#endif

#include <memory>
#include <vector>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/test_utils.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <utils/FileMap.h>
#include <ziparchive/zip_archive.h>
#include <ziparchive/zip_archive_stream_entry.h>

static std::string test_data_dir;

static const std::string kMissingZip = "missing.zip";
static const std::string kValidZip = "valid.zip";
static const std::string kLargeZip = "large.zip";
static const std::string kBadCrcZip = "bad_crc.zip";
static const std::string kUpdateZip = "update.zip";


static const std::vector<uint8_t> kATxtContents {
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
  '\n'
};

static const std::vector<uint8_t> kATxtContentsCompressed {
  'K', 'L', 'J', 'N', 'I', 'M', 'K', 207, 'H',
  132, 210, '\\', '\0'
};

static const std::vector<uint8_t> kBTxtContents {
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
  '\n'
};

static const std::string kATxtName("a.txt");
static const std::string kBTxtName("b.txt");
static const std::string kNonexistentTxtName("nonexistent.txt");
static const std::string kEmptyTxtName("empty.txt");
static const std::string kLargeCompressTxtName("compress.txt");
static const std::string kLargeUncompressTxtName("uncompress.txt");

static int32_t OpenArchiveWrapper(const std::string& name,
                                  ZipArchiveHandle* handle) {
  const std::string abs_path = test_data_dir + "/" + name;
  return OpenArchive(abs_path.c_str(), handle);
}


static void AssertNameEquals(const std::string& name_str,
                             const ZipString& name) {
  ASSERT_EQ(name_str.size(), name.name_length);
  ASSERT_EQ(0, memcmp(name_str.c_str(), name.name, name.name_length));
}

static void SetZipString(ZipString* zip_str, const std::string& str) {
  zip_str->name = reinterpret_cast<const uint8_t*>(str.c_str());
  zip_str->name_length = str.size();
}

TEST(ziparchive, Open) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  CloseArchive(handle);
}

TEST(ziparchive, OpenMissing) {
  ZipArchiveHandle handle;
  ASSERT_NE(0, OpenArchiveWrapper(kMissingZip, &handle));

  // Confirm the file descriptor is not going to be mistaken for a valid one.
  ASSERT_EQ(-1, GetFileDescriptor(handle));
}

TEST(ziparchive, OpenAssumeFdOwnership) {
  int fd = open((test_data_dir + "/" + kValidZip).c_str(), O_RDONLY | O_BINARY);
  ASSERT_NE(-1, fd);
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveFd(fd, "OpenWithAssumeFdOwnership", &handle));
  CloseArchive(handle);
  ASSERT_EQ(-1, lseek(fd, 0, SEEK_SET));
  ASSERT_EQ(EBADF, errno);
}

TEST(ziparchive, OpenDoNotAssumeFdOwnership) {
  int fd = open((test_data_dir + "/" + kValidZip).c_str(), O_RDONLY | O_BINARY);
  ASSERT_NE(-1, fd);
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveFd(fd, "OpenWithAssumeFdOwnership", &handle, false));
  CloseArchive(handle);
  ASSERT_EQ(0, lseek(fd, 0, SEEK_SET));
  close(fd);
}

TEST(ziparchive, Iteration) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  void* iteration_cookie;
  ASSERT_EQ(0, StartIteration(handle, &iteration_cookie, nullptr, nullptr));

  ZipEntry data;
  ZipString name;

  // b/c.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/c.txt", name);

  // b/d.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/d.txt", name);

  // a.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("a.txt", name);

  // b.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b.txt", name);

  // b/
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/", name);

  // End of iteration.
  ASSERT_EQ(-1, Next(iteration_cookie, &data, &name));

  CloseArchive(handle);
}

TEST(ziparchive, IterationWithPrefix) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  void* iteration_cookie;
  ZipString prefix("b/");
  ASSERT_EQ(0, StartIteration(handle, &iteration_cookie, &prefix, nullptr));

  ZipEntry data;
  ZipString name;

  // b/c.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/c.txt", name);

  // b/d.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/d.txt", name);

  // b/
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/", name);

  // End of iteration.
  ASSERT_EQ(-1, Next(iteration_cookie, &data, &name));

  CloseArchive(handle);
}

TEST(ziparchive, IterationWithSuffix) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  void* iteration_cookie;
  ZipString suffix(".txt");
  ASSERT_EQ(0, StartIteration(handle, &iteration_cookie, nullptr, &suffix));

  ZipEntry data;
  ZipString name;

  // b/c.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/c.txt", name);

  // b/d.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/d.txt", name);

  // a.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("a.txt", name);

  // b.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b.txt", name);

  // End of iteration.
  ASSERT_EQ(-1, Next(iteration_cookie, &data, &name));

  CloseArchive(handle);
}

TEST(ziparchive, IterationWithPrefixAndSuffix) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  void* iteration_cookie;
  ZipString prefix("b");
  ZipString suffix(".txt");
  ASSERT_EQ(0, StartIteration(handle, &iteration_cookie, &prefix, &suffix));

  ZipEntry data;
  ZipString name;

  // b/c.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/c.txt", name);

  // b/d.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/d.txt", name);

  // b.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b.txt", name);

  // End of iteration.
  ASSERT_EQ(-1, Next(iteration_cookie, &data, &name));

  CloseArchive(handle);
}

TEST(ziparchive, IterationWithBadPrefixAndSuffix) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  void* iteration_cookie;
  ZipString prefix("x");
  ZipString suffix("y");
  ASSERT_EQ(0, StartIteration(handle, &iteration_cookie, &prefix, &suffix));

  ZipEntry data;
  ZipString name;

  // End of iteration.
  ASSERT_EQ(-1, Next(iteration_cookie, &data, &name));

  CloseArchive(handle);
}

TEST(ziparchive, FindEntry) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  ZipEntry data;
  ZipString name;
  SetZipString(&name, kATxtName);
  ASSERT_EQ(0, FindEntry(handle, name, &data));

  // Known facts about a.txt, from zipinfo -v.
  ASSERT_EQ(63, data.offset);
  ASSERT_EQ(kCompressDeflated, data.method);
  ASSERT_EQ(static_cast<uint32_t>(17), data.uncompressed_length);
  ASSERT_EQ(static_cast<uint32_t>(13), data.compressed_length);
  ASSERT_EQ(0x950821c5, data.crc32);
  ASSERT_EQ(static_cast<uint32_t>(0x438a8005), data.mod_time);

  // An entry that doesn't exist. Should be a negative return code.
  ZipString absent_name;
  SetZipString(&absent_name, kNonexistentTxtName);
  ASSERT_LT(FindEntry(handle, absent_name, &data), 0);

  CloseArchive(handle);
}

TEST(ziparchive, TestInvalidDeclaredLength) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper("declaredlength.zip", &handle));

  void* iteration_cookie;
  ASSERT_EQ(0, StartIteration(handle, &iteration_cookie, nullptr, nullptr));

  ZipString name;
  ZipEntry data;

  ASSERT_EQ(Next(iteration_cookie, &data, &name), 0);
  ASSERT_EQ(Next(iteration_cookie, &data, &name), 0);

  CloseArchive(handle);
}

TEST(ziparchive, ExtractToMemory) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  // An entry that's deflated.
  ZipEntry data;
  ZipString a_name;
  SetZipString(&a_name, kATxtName);
  ASSERT_EQ(0, FindEntry(handle, a_name, &data));
  const uint32_t a_size = data.uncompressed_length;
  ASSERT_EQ(a_size, kATxtContents.size());
  uint8_t* buffer = new uint8_t[a_size];
  ASSERT_EQ(0, ExtractToMemory(handle, &data, buffer, a_size));
  ASSERT_EQ(0, memcmp(buffer, kATxtContents.data(), a_size));
  delete[] buffer;

  // An entry that's stored.
  ZipString b_name;
  SetZipString(&b_name, kBTxtName);
  ASSERT_EQ(0, FindEntry(handle, b_name, &data));
  const uint32_t b_size = data.uncompressed_length;
  ASSERT_EQ(b_size, kBTxtContents.size());
  buffer = new uint8_t[b_size];
  ASSERT_EQ(0, ExtractToMemory(handle, &data, buffer, b_size));
  ASSERT_EQ(0, memcmp(buffer, kBTxtContents.data(), b_size));
  delete[] buffer;

  CloseArchive(handle);
}

static const uint32_t kEmptyEntriesZip[] = {
      0x04034b50, 0x0000000a, 0x63600000, 0x00004438, 0x00000000, 0x00000000,
      0x00090000, 0x6d65001c, 0x2e797470, 0x55747874, 0x03000954, 0x52e25c13,
      0x52e25c24, 0x000b7875, 0x42890401, 0x88040000, 0x50000013, 0x1e02014b,
      0x00000a03, 0x60000000, 0x00443863, 0x00000000, 0x00000000, 0x09000000,
      0x00001800, 0x00000000, 0xa0000000, 0x00000081, 0x706d6500, 0x742e7974,
      0x54557478, 0x13030005, 0x7552e25c, 0x01000b78, 0x00428904, 0x13880400,
      0x4b500000, 0x00000605, 0x00010000, 0x004f0001, 0x00430000, 0x00000000 };

// This is a zip file containing a single entry (ab.txt) that contains
// 90072 repetitions of the string "ab\n" and has an uncompressed length
// of 270216 bytes.
static const uint16_t kAbZip[] = {
  0x4b50, 0x0403, 0x0014, 0x0000, 0x0008, 0x51d2, 0x4698, 0xc4b0,
  0x2cda, 0x011b, 0x0000, 0x1f88, 0x0004, 0x0006, 0x001c, 0x6261,
  0x742e, 0x7478, 0x5455, 0x0009, 0x7c03, 0x3a09, 0x7c55, 0x3a09,
  0x7555, 0x0b78, 0x0100, 0x8904, 0x0042, 0x0400, 0x1388, 0x0000,
  0xc2ed, 0x0d31, 0x0000, 0x030c, 0x7fa0, 0x3b2e, 0x22ff, 0xa2aa,
  0x841f, 0x45fc, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0xdd55, 0x502c, 0x014b, 0x1e02,
  0x1403, 0x0000, 0x0800, 0xd200, 0x9851, 0xb046, 0xdac4, 0x1b2c,
  0x0001, 0x8800, 0x041f, 0x0600, 0x1800, 0x0000, 0x0000, 0x0100,
  0x0000, 0xa000, 0x0081, 0x0000, 0x6100, 0x2e62, 0x7874, 0x5574,
  0x0554, 0x0300, 0x097c, 0x553a, 0x7875, 0x000b, 0x0401, 0x4289,
  0x0000, 0x8804, 0x0013, 0x5000, 0x054b, 0x0006, 0x0000, 0x0100,
  0x0100, 0x4c00, 0x0000, 0x5b00, 0x0001, 0x0000, 0x0000
};

static const std::string kAbTxtName("ab.txt");
static const size_t kAbUncompressedSize = 270216;

TEST(ziparchive, EmptyEntries) {
  TemporaryFile tmp_file;
  ASSERT_NE(-1, tmp_file.fd);
  ASSERT_TRUE(android::base::WriteFully(tmp_file.fd, kEmptyEntriesZip, sizeof(kEmptyEntriesZip)));

  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveFd(tmp_file.fd, "EmptyEntriesTest", &handle));

  ZipEntry entry;
  ZipString empty_name;
  SetZipString(&empty_name, kEmptyTxtName);
  ASSERT_EQ(0, FindEntry(handle, empty_name, &entry));
  ASSERT_EQ(static_cast<uint32_t>(0), entry.uncompressed_length);
  uint8_t buffer[1];
  ASSERT_EQ(0, ExtractToMemory(handle, &entry, buffer, 1));


  TemporaryFile tmp_output_file;
  ASSERT_NE(-1, tmp_output_file.fd);
  ASSERT_EQ(0, ExtractEntryToFile(handle, &entry, tmp_output_file.fd));

  struct stat stat_buf;
  ASSERT_EQ(0, fstat(tmp_output_file.fd, &stat_buf));
  ASSERT_EQ(0, stat_buf.st_size);
}

TEST(ziparchive, EntryLargerThan32K) {
  TemporaryFile tmp_file;
  ASSERT_NE(-1, tmp_file.fd);
  ASSERT_TRUE(android::base::WriteFully(tmp_file.fd, reinterpret_cast<const uint8_t*>(kAbZip),
                         sizeof(kAbZip) - 1));
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveFd(tmp_file.fd, "EntryLargerThan32KTest", &handle));

  ZipEntry entry;
  ZipString ab_name;
  SetZipString(&ab_name, kAbTxtName);
  ASSERT_EQ(0, FindEntry(handle, ab_name, &entry));
  ASSERT_EQ(kAbUncompressedSize, entry.uncompressed_length);

  // Extract the entry to memory.
  std::vector<uint8_t> buffer(kAbUncompressedSize);
  ASSERT_EQ(0, ExtractToMemory(handle, &entry, &buffer[0], buffer.size()));

  // Extract the entry to a file.
  TemporaryFile tmp_output_file;
  ASSERT_NE(-1, tmp_output_file.fd);
  ASSERT_EQ(0, ExtractEntryToFile(handle, &entry, tmp_output_file.fd));

  // Make sure the extracted file size is as expected.
  struct stat stat_buf;
  ASSERT_EQ(0, fstat(tmp_output_file.fd, &stat_buf));
  ASSERT_EQ(kAbUncompressedSize, static_cast<size_t>(stat_buf.st_size));

  // Read the file back to a buffer and make sure the contents are
  // the same as the memory buffer we extracted directly to.
  std::vector<uint8_t> file_contents(kAbUncompressedSize);
  ASSERT_EQ(0, lseek64(tmp_output_file.fd, 0, SEEK_SET));
  ASSERT_TRUE(android::base::ReadFully(tmp_output_file.fd, &file_contents[0],
                                       file_contents.size()));
  ASSERT_EQ(file_contents, buffer);

  for (int i = 0; i < 90072; ++i) {
    const uint8_t* line = &file_contents[0] + (3 * i);
    ASSERT_EQ('a', line[0]);
    ASSERT_EQ('b', line[1]);
    ASSERT_EQ('\n', line[2]);
  }
}

TEST(ziparchive, TrailerAfterEOCD) {
  TemporaryFile tmp_file;
  ASSERT_NE(-1, tmp_file.fd);

  // Create a file with 8 bytes of random garbage.
  static const uint8_t trailer[] = { 'A' ,'n', 'd', 'r', 'o', 'i', 'd', 'z' };
  ASSERT_TRUE(android::base::WriteFully(tmp_file.fd, kEmptyEntriesZip, sizeof(kEmptyEntriesZip)));
  ASSERT_TRUE(android::base::WriteFully(tmp_file.fd, trailer, sizeof(trailer)));

  ZipArchiveHandle handle;
  ASSERT_GT(0, OpenArchiveFd(tmp_file.fd, "EmptyEntriesTest", &handle));
}

TEST(ziparchive, ExtractToFile) {
  TemporaryFile tmp_file;
  ASSERT_NE(-1, tmp_file.fd);
  const uint8_t data[8] = { '1', '2', '3', '4', '5', '6', '7', '8' };
  const size_t data_size = sizeof(data);

  ASSERT_TRUE(android::base::WriteFully(tmp_file.fd, data, data_size));

  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  ZipEntry entry;
  ZipString name;
  SetZipString(&name, kATxtName);
  ASSERT_EQ(0, FindEntry(handle, name, &entry));
  ASSERT_EQ(0, ExtractEntryToFile(handle, &entry, tmp_file.fd));


  // Assert that the first 8 bytes of the file haven't been clobbered.
  uint8_t read_buffer[data_size];
  ASSERT_EQ(0, lseek64(tmp_file.fd, 0, SEEK_SET));
  ASSERT_TRUE(android::base::ReadFully(tmp_file.fd, read_buffer, data_size));
  ASSERT_EQ(0, memcmp(read_buffer, data, data_size));

  // Assert that the remainder of the file contains the incompressed data.
  std::vector<uint8_t> uncompressed_data(entry.uncompressed_length);
  ASSERT_TRUE(android::base::ReadFully(tmp_file.fd, uncompressed_data.data(),
                                       entry.uncompressed_length));
  ASSERT_EQ(0, memcmp(&uncompressed_data[0], kATxtContents.data(),
                      kATxtContents.size()));

  // Assert that the total length of the file is sane
  ASSERT_EQ(static_cast<ssize_t>(data_size + kATxtContents.size()),
            lseek64(tmp_file.fd, 0, SEEK_END));
}

#if !defined(_WIN32)
class NewThreadInfo {
 public:
  ZipArchiveHandle za;
  ZipEntry entry;
  int fd;
  bool data_state;
  size_t data_written;
  size_t target_count;

  pthread_mutex_t mu;
  pthread_cond_t cv;

  NewThreadInfo() : data_state(false), data_written(0), target_count(0) {
  }
};

static void TestWriter(const uint8_t* data, void* cookie) {
  NewThreadInfo* info = reinterpret_cast<NewThreadInfo*>(cookie);

  ASSERT_TRUE(android::base::WriteFully(info->fd, data, info->target_count));
  info->data_written = info->target_count;
}

static bool ReceiveNewData(const uint8_t* data, size_t size, void* cookie) {
  NewThreadInfo* nti = reinterpret_cast<NewThreadInfo*>(cookie);

  while (size > 0) {
    pthread_mutex_lock(&nti->mu);
    while (nti->data_state == false) {
        pthread_cond_wait(&nti->cv, &nti->mu);
    }
    pthread_mutex_unlock(&nti->mu);

    nti->data_written = 0;
    if (nti->target_count > size) {
      nti->target_count = size;
    }
    TestWriter(data, cookie);
    data += nti->target_count;
    size -= nti->target_count;

    if (nti->data_written == nti->target_count) {
      pthread_mutex_lock(&nti->mu);
      nti->data_state = false;
      pthread_cond_broadcast(&nti->cv);
      pthread_mutex_unlock(&nti->mu);
    }
  }
  return true;
}

static void* UnzipNewData(void* cookie) {
  NewThreadInfo* nti = reinterpret_cast<NewThreadInfo*>(cookie);
  ProcessZipEntryContents(nti->za, &nti->entry, &ReceiveNewData, nti);
  return nullptr;
}

// This test mimics the useage in OTA updater. We stream the content of a zip
// entry out of the archive and hold the writer until its turn to go.
TEST(ziparchive, ProcessZipEntryContents) {
  TemporaryFile tmp_file;
  ASSERT_NE(-1, tmp_file.fd);

  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  ZipEntry entry;
  ZipString name;
  SetZipString(&name, kATxtName);
  ASSERT_EQ(0, FindEntry(handle, name, &entry));

  NewThreadInfo* info = new NewThreadInfo();
  info->za = handle;
  info->entry = entry;
  info->fd = tmp_file.fd;
  pthread_mutex_init(&info->mu, nullptr);
  pthread_cond_init(&info->cv, nullptr);
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
  pthread_t thread;

  pthread_create(&thread, &attr, UnzipNewData, info);

  size_t written = 0;
  size_t size = entry.uncompressed_length;
  while (written < size) {
    pthread_mutex_lock(&info->mu);
    info->data_state = true;
    // Write 1/3 of the data at a time until we finish writing all the entry
    // contents.
    size_t to_write = (size/3 < size - written ? size/3 : size - written);
    info->target_count = to_write;
    pthread_cond_broadcast(&info->cv);

    while(info->data_state) {
      pthread_cond_wait(&info->cv, &info->mu);
    }

    pthread_mutex_unlock(&info->mu);
    written += to_write;
  }

  std::vector<uint8_t> read_data(entry.uncompressed_length);
  ASSERT_EQ(0, lseek64(tmp_file.fd, 0, SEEK_SET));
  ASSERT_TRUE(android::base::ReadFully(tmp_file.fd, read_data.data(), entry.uncompressed_length));
  ASSERT_EQ(read_data.size(), kATxtContents.size());
  ASSERT_EQ(0, memcmp(read_data.data(), kATxtContents.data(), kATxtContents.size()));
}

TEST(ziparchive, ExtractPackageRecursive) {
  TemporaryDir td;
  ASSERT_NE(td.path, nullptr);
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  ExtractPackageRecursive(handle, "", td.path, nullptr, nullptr);

  std::string path(td.path);
  android::base::unique_fd fd(open((path + "/a.txt").c_str(), O_RDONLY));
  ASSERT_NE(fd, -1);
  std::vector<uint8_t> read_data;
  read_data.resize(kATxtContents.size());
  ASSERT_TRUE(android::base::ReadFully(fd.get(), read_data.data(), read_data.size()));
  ASSERT_EQ(0, memcmp(read_data.data(), kATxtContents.data(), kATxtContents.size()));

  fd.reset(open((path + "/b.txt").c_str(), O_RDONLY));
  ASSERT_NE(fd, -1);
  fd.reset(open((path + "/b/c.txt").c_str(), O_RDONLY));
  ASSERT_NE(fd, -1);
  fd.reset(open((path + "/b/d.txt").c_str(), O_RDONLY));
  ASSERT_NE(fd, -1);
  read_data.resize(kBTxtContents.size());
  ASSERT_TRUE(android::base::ReadFully(fd.get(), read_data.data(), read_data.size()));
  ASSERT_EQ(0, memcmp(read_data.data(), kBTxtContents.data(), kBTxtContents.size()));
}

TEST(ziparchive, OpenFromMemory) {
  android::base::unique_fd fd(open((test_data_dir + "/" + kUpdateZip).c_str(), O_RDONLY | O_BINARY));
  ASSERT_NE(-1, fd);
  struct stat sb;
  ASSERT_EQ(0, fstat(fd, &sb));
  size_t total_size = sb.st_size;
  size_t block_size = sb.st_blksize;

  TemporaryFile tmp_map, tmp_block;
  ASSERT_NE(-1, tmp_map.fd);
  ASSERT_NE(-1, tmp_block.fd);
  ASSERT_TRUE(android::base::WriteStringToFd(
      android::base::StringPrintf("%s\n", tmp_block.path), tmp_map.fd));
  ASSERT_TRUE(android::base::WriteStringToFd(
      android::base::StringPrintf("%zu %zu\n", total_size, block_size), tmp_map.fd));

  size_t ranges = (total_size - 1) / block_size + 1;
  ASSERT_TRUE(android::base::WriteStringToFd(
      android::base::StringPrintf("%zu\n", ranges), tmp_map.fd));

  std::vector<uint8_t> buffer;
  buffer.resize(total_size);
  ASSERT_TRUE(android::base::ReadFully(fd, buffer.data(), total_size));

  uint8_t zeros[block_size];
  memset(zeros, 0, block_size);
  size_t written = 0;
  size_t start_block = 0;
  while (written < total_size) {
    size_t to_write = (total_size - written) < block_size ? (total_size - written) : block_size;
    ASSERT_TRUE(android::base::WriteFully(tmp_block.fd, zeros, block_size));
    ASSERT_TRUE(android::base::WriteFully(tmp_block.fd, buffer.data() + written, to_write));
    written += to_write;
    ASSERT_TRUE(android::base::WriteStringToFd(
        android::base::StringPrintf("%zu %zu\n", start_block + 1, start_block + 2), tmp_map.fd));
    start_block += 2;
  }

  android::FileMap block_map;
  block_map.createFromBlockFile(tmp_map.path);
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveFromMemory(&block_map, &handle));
  static constexpr const char* BINARY_PATH = "META-INF/com/google/android/update-binary";
  ZipString binary_path(BINARY_PATH);
  ZipEntry binary_entry;
  ASSERT_EQ(0, FindEntry(handle, binary_path, &binary_entry));
  TemporaryFile tmp_binary;
  ASSERT_NE(-1, tmp_binary.fd);
  ASSERT_EQ(0, ExtractEntryToFile(handle, &binary_entry, tmp_binary.fd));
}
#endif

static void ZipArchiveStreamTest(
    ZipArchiveHandle& handle, const std::string& entry_name, bool raw,
    bool verified, ZipEntry* entry, std::vector<uint8_t>* read_data) {
  ZipString name;
  SetZipString(&name, entry_name);
  ASSERT_EQ(0, FindEntry(handle, name, entry));
  std::unique_ptr<ZipArchiveStreamEntry> stream;
  if (raw) {
    stream.reset(ZipArchiveStreamEntry::CreateRaw(handle, *entry));
    if (entry->method == kCompressStored) {
      read_data->resize(entry->uncompressed_length);
    } else {
      read_data->resize(entry->compressed_length);
    }
  } else {
    stream.reset(ZipArchiveStreamEntry::Create(handle, *entry));
    read_data->resize(entry->uncompressed_length);
  }
  uint8_t* read_data_ptr = read_data->data();
  ASSERT_TRUE(stream.get() != nullptr);
  const std::vector<uint8_t>* data;
  uint64_t total_size = 0;
  while ((data = stream->Read()) != nullptr) {
    total_size += data->size();
    memcpy(read_data_ptr, data->data(), data->size());
    read_data_ptr += data->size();
  }
  ASSERT_EQ(verified, stream->Verify());
  ASSERT_EQ(total_size, read_data->size());
}

static void ZipArchiveStreamTestUsingContents(
    const std::string& zip_file, const std::string& entry_name,
    const std::vector<uint8_t>& contents, bool raw) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(zip_file, &handle));

  ZipEntry entry;
  std::vector<uint8_t> read_data;
  ZipArchiveStreamTest(handle, entry_name, raw, true, &entry, &read_data);

  ASSERT_EQ(contents.size(), read_data.size());
  ASSERT_TRUE(memcmp(read_data.data(), contents.data(), read_data.size()) == 0);

  CloseArchive(handle);
}

static void ZipArchiveStreamTestUsingMemory(const std::string& zip_file, const std::string& entry_name) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(zip_file, &handle));

  ZipEntry entry;
  std::vector<uint8_t> read_data;
  ZipArchiveStreamTest(handle, entry_name, false, true, &entry, &read_data);

  std::vector<uint8_t> cmp_data(entry.uncompressed_length);
  ASSERT_EQ(entry.uncompressed_length, read_data.size());
  ASSERT_EQ(0, ExtractToMemory(handle, &entry, cmp_data.data(), cmp_data.size()));
  ASSERT_TRUE(memcmp(read_data.data(), cmp_data.data(), read_data.size()) == 0);

  CloseArchive(handle);
}

TEST(ziparchive, StreamCompressed) {
  ZipArchiveStreamTestUsingContents(kValidZip, kATxtName, kATxtContents, false);
}

TEST(ziparchive, StreamUncompressed) {
  ZipArchiveStreamTestUsingContents(kValidZip, kBTxtName, kBTxtContents, false);
}

TEST(ziparchive, StreamRawCompressed) {
  ZipArchiveStreamTestUsingContents(kValidZip, kATxtName, kATxtContentsCompressed, true);
}

TEST(ziparchive, StreamRawUncompressed) {
  ZipArchiveStreamTestUsingContents(kValidZip, kBTxtName, kBTxtContents, true);
}

TEST(ziparchive, StreamLargeCompressed) {
  ZipArchiveStreamTestUsingMemory(kLargeZip, kLargeCompressTxtName);
}

TEST(ziparchive, StreamLargeUncompressed) {
  ZipArchiveStreamTestUsingMemory(kLargeZip, kLargeUncompressTxtName);
}

TEST(ziparchive, StreamCompressedBadCrc) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kBadCrcZip, &handle));

  ZipEntry entry;
  std::vector<uint8_t> read_data;
  ZipArchiveStreamTest(handle, kATxtName, false, false, &entry, &read_data);

  CloseArchive(handle);
}

TEST(ziparchive, StreamUncompressedBadCrc) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kBadCrcZip, &handle));

  ZipEntry entry;
  std::vector<uint8_t> read_data;
  ZipArchiveStreamTest(handle, kBTxtName, false, false, &entry, &read_data);

  CloseArchive(handle);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);

  static struct option options[] = {
    { "test_data_dir", required_argument, nullptr, 't' },
    { nullptr, 0, nullptr, 0 }
  };

  while (true) {
    int option_index;
    const int c = getopt_long_only(argc, argv, "", options, &option_index);
    if (c == -1) {
      break;
    }

    if (c == 't') {
      test_data_dir = optarg;
    }
  }

  if (test_data_dir.size() == 0) {
    printf("Test data flag (--test_data_dir) required\n\n");
    return -1;
  }

  if (test_data_dir[0] != '/') {
    std::vector<char> cwd_buffer(1024);
    const char* cwd = getcwd(cwd_buffer.data(), cwd_buffer.size() - 1);
    if (cwd == nullptr) {
      printf("Cannot get current working directory, use an absolute path instead, was %s\n\n",
             test_data_dir.c_str());
      return -2;
    }
    test_data_dir = '/' + test_data_dir;
    test_data_dir = cwd + test_data_dir;
  }

  return RUN_ALL_TESTS();
}

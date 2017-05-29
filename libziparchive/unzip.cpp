/*
 * Copyright (C) 2017 The Android Open Source Project
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
#include <error.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/strings.h>
#include <ziparchive/zip_archive.h>

enum OverwriteMode {
  kAlways,
  kNever,
  kPrompt,
};

static OverwriteMode overwrite_mode = kPrompt;
static const char* flag_d = nullptr;
static bool flag_l = false;
static bool flag_p = false;
static bool flag_q = false;
static bool flag_v = false;
static const char* archive_name = nullptr;
static uint64_t total_uncompressed_length = 0;
static uint64_t total_compressed_length = 0;
static size_t file_count = 0;

// TODO: move from test to zip_archive.h?
static tm GetModificationTime(const ZipEntry& entry) {
  tm t = {};

  t.tm_hour = (entry.mod_time >> 11) & 0x1f;
  t.tm_min = (entry.mod_time >> 5) & 0x3f;
  t.tm_sec = (entry.mod_time & 0x1f) << 1;

  t.tm_year = ((entry.mod_time >> 25) & 0x7f) + 80;
  t.tm_mon = ((entry.mod_time >> 21) & 0xf) - 1;
  t.tm_mday = (entry.mod_time >> 16) & 0x1f;

  return t;
}

static bool MakeDirectoryHierarchy(const std::string& path) {
  // stat rather than lstat because a symbolic link to a directory is fine too.
  struct stat sb;
  if (stat(path.c_str(), &sb) != -1 && S_ISDIR(sb.st_mode)) return true;

  // Ensure the parent directories exist first.
  if (!MakeDirectoryHierarchy(android::base::Dirname(path))) return false;

  // Then try to create this directory.
  return (mkdir(path.c_str(), 0777) != -1);
}

static std::string Name(const ZipString& name) {
  return std::string(name.name, name.name + name.name_length);
}

static int CompressionRatio(int64_t uncompressed, int64_t compressed) {
  if (uncompressed == 0) return 0;
  return (100LL * (uncompressed - compressed)) / uncompressed;
}

static void ShowHeader() {
  if (!flag_q) printf("Archive:  %s\n", archive_name);
  if (flag_v) {
    printf(
        " Length   Method    Size  Cmpr    Date    Time   CRC-32   Name\n"
        "--------  ------  ------- ---- ---------- ----- --------  ----\n");
  } else if (flag_l) {
    printf(
        "  Length      Date    Time    Name\n"
        "---------  ---------- -----   ----\n");
  }
}

static void ShowFooter() {
  if (flag_v) {
    printf(
        "--------          -------  ---                            -------\n"
        "%8" PRId64 "         %8" PRId64 " %3d%%                            %zu files\n",
        total_uncompressed_length, total_compressed_length,
        CompressionRatio(total_uncompressed_length, total_compressed_length), file_count);
  } else if (flag_l) {
    printf(
        "---------                     -------\n"
        "%9" PRId64 "                     %zu files\n",
        total_uncompressed_length, file_count);
  }
}

static bool PromptOverwrite(const std::string& dst) {
  // TODO: [r]ename?
  printf("replace %s? [y]es, [n]o, [A]ll, [N]one: ", dst.c_str());
  fflush(stdout);
  while (true) {
    char* line = nullptr;
    size_t n;
    if (getline(&line, &n, stdin) == -1) {
      error(1, 0, "(EOF/read error; assuming [N]one...)");
      overwrite_mode = kNever;
      return false;
    }
    if (n == 0) continue;
    char cmd = line[0];
    free(line);
    switch (cmd) {
      case 'y':
        return true;
      case 'n':
        return false;
      case 'A':
        overwrite_mode = kAlways;
        return true;
      case 'N':
        overwrite_mode = kNever;
        return false;
    }
  }
}

static void ExtractToPipe(ZipArchiveHandle zah, ZipEntry& entry, const std::string& name) {
  // We need to extract to memory because ExtractEntryToFile insists on
  // being able to seek and truncate, and you can't do that with stdout.
  uint8_t* buffer = new uint8_t[entry.uncompressed_length];
  int err = ExtractToMemory(zah, &entry, buffer, entry.uncompressed_length);
  if (err < 0) {
    error(1, 0, "failed to extract %s: %s", name.c_str(), ErrorCodeString(err));
  }
  if (!android::base::WriteFully(1, buffer, entry.uncompressed_length)) {
    error(1, errno, "failed to write %s to stdout", name.c_str());
  }
  delete[] buffer;
}

static void ExtractOne(ZipArchiveHandle zah, ZipEntry& entry, const std::string& name) {
  // Bad filename?
  if (android::base::StartsWith(name, "/") || android::base::StartsWith(name, "../") ||
      name.find("/../") != std::string::npos) {
    error(1, 0, "bad filename %s", name.c_str());
  }

  // Where are we actually extracting to?
  std::string dst;
  if (flag_d) dst = flag_d;
  if (!android::base::EndsWith(dst, "/")) dst += '/';
  dst += name;

  // Ensure the directory hierarchy exists.
  if (!MakeDirectoryHierarchy(android::base::Dirname(dst))) {
    error(1, errno, "couldn't create directory hierarchy for %s", dst.c_str());
  }

  // Create the file.
  int fd = open(dst.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC | O_EXCL, 0666);
  if (fd == -1 && errno == EEXIST) {
    if (overwrite_mode == kNever) return;
    if (overwrite_mode == kPrompt && !PromptOverwrite(dst)) return;
    // Either overwrite_mode is kAlways or the user consented to this specific case.
    fd = open(dst.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC | O_TRUNC, 0666);
  }
  if (fd == -1) error(1, errno, "couldn't create file %s", dst.c_str());

  // Actually extract into the file.
  printf("  inflating: %s\n", dst.c_str());
  int err = ExtractEntryToFile(zah, &entry, fd);
  if (err < 0) error(1, 0, "failed to extract %s: %s", dst.c_str(), ErrorCodeString(err));
  close(fd);
}

static void UnzipOne(ZipArchiveHandle zah, ZipEntry& entry, const std::string& name) {
  if (flag_l || flag_v) {
    // -l or -lv or -lq or -v.
    tm t = GetModificationTime(entry);
    char time[32];
    snprintf(time, sizeof(time), "%04d-%02d-%02d %02d:%02d", t.tm_year + 1900, t.tm_mon + 1,
             t.tm_mday, t.tm_hour, t.tm_min);
    if (flag_v) {
      printf("%8d  %s  %7d %3d%% %s %08x  %s\n", entry.uncompressed_length,
             (entry.method == kCompressStored) ? "Stored" : "Defl:N", entry.compressed_length,
             CompressionRatio(entry.uncompressed_length, entry.compressed_length), time,
             entry.crc32, name.c_str());
    } else {
      printf("%9d  %s   %s\n", entry.uncompressed_length, time, name.c_str());
    }
  } else {
    // Actually extract.
    if (flag_p) {
      ExtractToPipe(zah, entry, name);
    } else {
      ExtractOne(zah, entry, name);
    }
  }
  total_uncompressed_length += entry.uncompressed_length;
  total_compressed_length += entry.compressed_length;
  ++file_count;
}

static void ShowHelp(bool full) {
  fprintf(full ? stdout : stderr, "usage: unzip [-d DIR] [-lnopqv] ZIP [FILE...]\n");
  if (!full) exit(EXIT_FAILURE);

  printf(
      "\n"
      "Extract FILEs from ZIP archive. Default is all files.\n"
      "\n"
      "-d DIR	Extract into DIR\n"
      "-l	List contents (-lq excludes archive name, -lv is verbose)\n"
      "-n	Never overwrite files (default: prompt)\n"
      "-o	Always overwrite files\n"
      "-p	Pipe to stdout\n"
      "-q	Quiet\n"
      "-v	List contents verbosely\n");
  // TODO: -x FILE... to exclude files?
  exit(EXIT_SUCCESS);
}

int main(int argc, char* argv[]) {
  static struct option opts[] = {
      {"help", no_argument, 0, 'h'},
  };
  int opt;
  while ((opt = getopt_long(argc, argv, "d:hlnopqv", opts, nullptr)) != -1) {
    switch (opt) {
      case 'd':
        flag_d = optarg;
        break;
      case 'h':
        ShowHelp(true);
        break;
      case 'l':
        flag_l = true;
        break;
      case 'n':
        overwrite_mode = kNever;
        break;
      case 'o':
        overwrite_mode = kAlways;
        break;
      case 'p':
        flag_p = flag_q = true;
        break;
      case 'q':
        flag_q = true;
        break;
      case 'v':
        flag_v = true;
        break;
      default:
        ShowHelp(false);
    }
  }

  if (optind >= argc) error(1, 0, "missing archive filename");
  archive_name = argv[optind++];

  // TODO: support "-" to unzip from stdin?

  ZipArchiveHandle zah;
  int32_t err;
  if ((err = OpenArchive(archive_name, &zah)) != 0) {
    error(1, 0, "couldn't open %s: %s", archive_name, ErrorCodeString(err));
  }

  ShowHeader();

  if (optind == argc) {
    // Operate on all files.
    // libziparchive iteration order doesn't match the central directory.
    // We could sort, but that would cost extra and wouldn't match either.
    void* cookie;
    if ((err = StartIteration(zah, &cookie, nullptr, nullptr)) != 0) {
      error(1, 0, "couldn't iterate %s: %s", archive_name, ErrorCodeString(err));
    }

    ZipEntry entry;
    ZipString name;
    while ((err = Next(cookie, &entry, &name)) >= 0) {
      UnzipOne(zah, entry, Name(name));
    }
    if (err < -1) error(1, 0, "failed iterating %s: %s", archive_name, ErrorCodeString(err));
    EndIteration(cookie);
  } else {
    // Operate on the supplied list of files only.
    while (optind < argc) {
      ZipString name(argv[optind++]);
      ZipEntry entry;
      if ((err = FindEntry(zah, name, &entry)) != 0) {
        error(1, 0, "failed to find %s: %s", Name(name).c_str(), ErrorCodeString(err));
      }
      UnzipOne(zah, entry, Name(name));
    }
  }

  ShowFooter();

  CloseArchive(zah);
  return 0;
}

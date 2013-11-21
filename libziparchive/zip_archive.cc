/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Read-only access to Zip archives, with minimal heap allocation.
 */
#include "zip_archive.h"

#include <zlib.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <log/log.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <JNIHelp.h>  // TEMP_FAILURE_RETRY may or may not be in unistd

#ifndef O_BINARY
#define O_BINARY 0
#endif

/*
 * Zip file constants.
 */
#define kEOCDSignature      0x06054b50
#define kEOCDLen            22
#define kEOCDNumEntries     8               // offset to #of entries in file
#define kEOCDSize           12              // size of the central directory
#define kEOCDFileOffset     16              // offset to central directory

#define kMaxCommentLen      65535           // longest possible in ushort
#define kMaxEOCDSearch      (kMaxCommentLen + kEOCDLen)

#define kLFHSignature       0x04034b50
#define kLFHLen             30              // excluding variable-len fields
#define kLFHGPBFlags        6               // general purpose bit flags
#define kLFHCRC             14              // offset to CRC
#define kLFHCompLen         18              // offset to compressed length
#define kLFHUncompLen       22              // offset to uncompressed length
#define kLFHNameLen         26              // offset to filename length
#define kLFHExtraLen        28              // offset to extra length

#define kCDESignature       0x02014b50
#define kCDELen             46              // excluding variable-len fields
#define kCDEMethod          10              // offset to compression method
#define kCDEModWhen         12              // offset to modification timestamp
#define kCDECRC             16              // offset to entry CRC
#define kCDECompLen         20              // offset to compressed length
#define kCDEUncompressed_length       24              // offset to uncompressed length
#define kCDENameLen         28              // offset to filename length
#define kCDEExtraLen        30              // offset to extra length
#define kCDECommentLen      32              // offset to comment length
#define kCDELocalOffset     42              // offset to local hdr

#define kDDOptSignature     0x08074b50      // *OPTIONAL* data descriptor signature
#define kDDSignatureLen     4
#define kDDLen              12
#define kDDMaxLen           16              // max of 16 bytes with a signature, 12 bytes without
#define kDDCrc32            0               // offset to crc32
#define kDDCompLen          4               // offset to compressed length
#define kDDUncompLen        8               // offset to uncompressed length

#define kGPBDDFlagMask      0x0008          // mask value that signifies that the entry has a DD

/*
 * The values we return for ZipEntry use 0 as an invalid value, so we
 * want to adjust the hash table index by a fixed amount.  Using a large
 * value helps insure that people don't mix & match arguments, e.g. with
 * entry indices.
 */
#define kZipEntryAdj 10000

#ifdef PAGE_SHIFT
#define SYSTEM_PAGE_SIZE (1 << PAGE_SHIFT)
#else
#define SYSTEM_PAGE_SIZE 4096
#endif

struct MemMapping {
  const uint8_t* addr;  // Start of data
  size_t length;  // Length of data

  uint8_t* base_address;  // page-aligned base address
  size_t base_length;  // length of mapping
};

/*
 * A Read-only Zip archive.
 *
 * We want "open" and "find entry by name" to be fast operations, and
 * we want to use as little memory as possible.  We memory-map the zip
 * central directory, and load a hash table with pointers to the filenames
 * (which aren't null-terminated).  The other fields are at a fixed offset
 * from the filename, so we don't need to extract those (but we do need
 * to byte-read and endian-swap them every time we want them).
 *
 * It's possible that somebody has handed us a massive (~1GB) zip archive,
 * so we can't expect to mmap the entire file.
 *
 * To speed comparisons when doing a lookup by name, we could make the mapping
 * "private" (copy-on-write) and null-terminate the filenames after verifying
 * the record structure.  However, this requires a private mapping of
 * every page that the Central Directory touches.  Easier to tuck a copy
 * of the string length into the hash table entry.
 */
struct ZipArchive {
  /* open Zip archive */
  int fd;

  /* mapped central directory area */
  off_t directory_offset;
  MemMapping directory_map;

  /* number of entries in the Zip archive */
  uint16_t num_entries;

  /*
   * We know how many entries are in the Zip archive, so we can have a
   * fixed-size hash table. We define a load factor of 0.75 and overallocat
   * so the maximum number entries can never be higher than
   * ((4 * UINT16_MAX) / 3 + 1) which can safely fit into a uint32_t.
   */
  uint32_t hash_table_size;
  ZipEntryName* hash_table;
};

// Returns 0 on success and negative values on failure.
static int MapFileSegment(const int fd, const off_t start, const size_t length,
                          MemMapping *mapping) {
  /* adjust to be page-aligned */
  const int adjust = start % SYSTEM_PAGE_SIZE;
  const off_t actual_start = start - adjust;
  const off_t actual_length = length + adjust;

  void* map_addr = mmap(NULL, actual_length, PROT_READ, MAP_FILE | MAP_SHARED,
      fd, actual_start);
  if (map_addr == MAP_FAILED) {
    ALOGW("mmap(%d, R, FILE|SHARED, %d, %d) failed: %s",
      actual_length, fd, actual_start, strerror(errno));
    return -1;
  }

  mapping->base_address = (uint8_t*) map_addr;
  mapping->base_length = actual_length;
  mapping->addr = (uint8_t*) map_addr + adjust;
  mapping->length = length;

  ALOGV("mmap seg (st=%d ln=%d): b=%p bl=%d ad=%p ln=%d",
      start, length, mapping->base_address, mapping->base_length,
      mapping->addr, mapping->length);

  return 0;
}

static void ReleaseMappedSegment(MemMapping* map) {
  if (map->base_address == 0 || map->base_length == 0) {
    return;
  }

  if (munmap(map->base_address, map->base_length) < 0) {
  ALOGW("munmap(%p, %d) failed: %s",
      map->base_address, (int)map->base_length, strerror(errno));
  } else {
    ALOGV("munmap(%p, %d) succeeded", map->base_address, map->base_length);
    free(map);
  }
}

static int WriteFully(int fd, const void* buf, size_t count,
                      const char* log_message) {
  while (count != 0) {
    ssize_t actual = TEMP_FAILURE_RETRY(write(fd, buf, count));
    if (actual < 0) {
      int err = errno;
      ALOGE("%s: write failed: %s", log_message, strerror(err));
      return err;
    } else if (actual != (ssize_t) count) {
      ALOGD("%s: partial write (will retry): (%d of %zd)",
          log_message, (int) actual, count);
      buf = (const void*) (((const uint8_t*) buf) + actual);
    }
    count -= actual;
  }

  return 0;
}

static int CopyFileToFile(int output_fd, int fd, size_t count) {
  const size_t kBufSize = 32768;
  unsigned char buf[kBufSize];

  while (count != 0) {
    size_t getSize = (count > kBufSize) ? kBufSize : count;

    ssize_t actual = TEMP_FAILURE_RETRY(read(fd, buf, getSize));
    if (actual != (ssize_t) getSize) {
      ALOGW("sysCopyFileToFile: copy read failed (%d vs %zd)",
          (int) actual, getSize);
      return -1;
    }

    if (WriteFully(output_fd, buf, getSize, "sysCopyFileToFile") != 0) {
      return -1;
    }

    count -= getSize;
  }

  return 0;
}

/*
 * Round up to the next highest power of 2.
 *
 * Found on http://graphics.stanford.edu/~seander/bithacks.html.
 */
static uint32_t RoundUpPower2(uint32_t val) {
  val--;
  val |= val >> 1;
  val |= val >> 2;
  val |= val >> 4;
  val |= val >> 8;
  val |= val >> 16;
  val++;

  return val;
}

static uint32_t ComputeHash(const char* str, uint16_t len) {
  uint32_t hash = 0;

  while (len--) {
    hash = hash * 31 + *str++;
  }

  return hash;
}

/*
 * Convert a ZipEntry to a hash table index, verifying that it's in a
 * valid range.
 */
static int64_t EntryToIndex(const ZipEntryName* hash_table,
                            const uint32_t hash_table_size,
                            const char* name, uint16_t length) {
  const uint32_t hash = ComputeHash(name, length);

  // NOTE: (hash_table_size - 1) is guaranteed to be non-negative.
  uint32_t ent = hash & (hash_table_size - 1);
  while (hash_table[ent].name != NULL) {
    if (hash_table[ent].name_length == length &&
        memcmp(hash_table[ent].name, name, length) == 0) {
      return ent;
    }

    ent = (ent + 1) & (hash_table_size - 1);
  }

  ALOGV("Zip: Unable to find entry %.*s", name_length, name);
  return -1;
}

/*
 * Add a new entry to the hash table.
 */
static int AddToHash(ZipEntryName *hash_table, const uint64_t hash_table_size,
                     const char* name, uint16_t length) {
  const uint64_t hash = ComputeHash(name, length);
  uint32_t ent = hash & (hash_table_size - 1);

  /*
   * We over-allocated the table, so we're guaranteed to find an empty slot.
   * Further, we guarantee that the hashtable size is not 0.
   */
  while (hash_table[ent].name != NULL) {
    if (hash_table[ent].name_length == length &&
        memcmp(hash_table[ent].name, name, length) == 0) {
      // We've found a duplicate entry. We don't accept it
      ALOGW("Zip: Found duplicate entry %.*s", length, name);
      return -1;
    }
    ent = (ent + 1) & (hash_table_size - 1);
  }

  hash_table[ent].name = name;
  hash_table[ent].name_length = length;
  return 0;
}

/*
 * Get 2 little-endian bytes.
 */
static uint16_t get2LE(const uint8_t* src) {
  return src[0] | (src[1] << 8);
}

/*
 * Get 4 little-endian bytes.
 */
static uint32_t get4LE(const uint8_t* src) {
  uint32_t result;

  result = src[0];
  result |= src[1] << 8;
  result |= src[2] << 16;
  result |= src[3] << 24;

  return result;
}

static int MapCentralDirectory0(int fd, const char* debug_file_name,
                                ZipArchive* archive, off_t file_length,
                                size_t read_amount, uint8_t* scan_buffer) {
  off_t search_start = file_length - read_amount;

  if (lseek(fd, search_start, SEEK_SET) != search_start) {
    ALOGW("Zip: seek %ld failed: %s", search_start, strerror(errno));
    return -1;
  }
  ssize_t actual = TEMP_FAILURE_RETRY(read(fd, scan_buffer, read_amount));
  if (actual != (ssize_t) read_amount) {
    ALOGW("Zip: read %zd failed: %s", read_amount, strerror(errno));
    return -1;
  }

  /*
   * Scan backward for the EOCD magic.  In an archive without a trailing
   * comment, we'll find it on the first try.  (We may want to consider
   * doing an initial minimal read; if we don't find it, retry with a
   * second read as above.)
   */
  int i;
  for (i = read_amount - kEOCDLen; i >= 0; i--) {
    if (scan_buffer[i] == 0x50 && get4LE(&scan_buffer[i]) == kEOCDSignature) {
      ALOGV("+++ Found EOCD at buf+%d", i);
      break;
    }
  }
  if (i < 0) {
    ALOGD("Zip: EOCD not found, %s is not zip", debug_file_name);
    return -1;
  }

  off_t eocd_offset = search_start + i;
  const uint8_t* eocd_ptr = scan_buffer + i;

  assert(eocd_offset < file_length);

  /*
   * Grab the CD offset and size, and the number of entries in the
   * archive.  Verify that they look reasonable. Widen dir_size and
   * dir_offset to the file offset type.
   */
  const uint32_t num_entries = get2LE(eocd_ptr + kEOCDNumEntries);
  const off_t dir_size = get4LE(eocd_ptr + kEOCDSize);
  const off_t dir_offset = get4LE(eocd_ptr + kEOCDFileOffset);

  if ((off_t) dir_offset + (off_t) dir_size > eocd_offset) {
    ALOGW("Zip: bad offsets (dir %ld, size %u, eocd %ld)",
        dir_offset, dir_size, eocd_offset);
    return -1;
  }
  if (num_entries == 0) {
    ALOGW("Zip: empty archive?");
    return -1;
  }

  ALOGV("+++ num_entries=%d dir_size=%d dir_offset=%d", num_entries, dir_size,
      dir_offset);

  /*
   * It all looks good.  Create a mapping for the CD, and set the fields
   * in archive.
   */
  const int result = MapFileSegment(fd, dir_offset, dir_size,
                    &(archive->directory_map));
  if (result) {
    ALOGW("Zip: cd map failed with return code %d", result);
    return result;
  }

  archive->num_entries = num_entries;
  archive->directory_offset = dir_offset;

  return 0;
}

/*
 * Find the zip Central Directory and memory-map it.
 *
 * On success, returns 0 after populating fields from the EOCD area:
 *   directory_offset
 *   directory_map
 *   num_entries
 */
static int MapCentralDirectory(int fd, const char* debug_file_name,
                               ZipArchive* archive) {
  /*
   * Get and test file length.
   */
  off_t file_length = lseek(fd, 0, SEEK_END);
  if (file_length < kEOCDLen) {
    ALOGV("Zip: length %ld is too small to be zip", file_length);
    return -1;
  }

  /*
   * Perform the traditional EOCD snipe hunt.
   *
   * We're searching for the End of Central Directory magic number,
   * which appears at the start of the EOCD block.  It's followed by
   * 18 bytes of EOCD stuff and up to 64KB of archive comment.  We
   * need to read the last part of the file into a buffer, dig through
   * it to find the magic number, parse some values out, and use those
   * to determine the extent of the CD.
   *
   * We start by pulling in the last part of the file.
   */
  size_t read_amount = kMaxEOCDSearch;
  if (file_length < off_t(read_amount)) {
    read_amount = file_length;
  }

  uint8_t* scan_buffer = (uint8_t*) malloc(read_amount);
  if (scan_buffer == NULL) {
    return -1;
  }

  int result = MapCentralDirectory0(fd, debug_file_name, archive,
      file_length, read_amount, scan_buffer);

  free(scan_buffer);
  return result;
}

/*
 * Parses the Zip archive's Central Directory.  Allocates and populates the
 * hash table.
 *
 * Returns 0 on success.
 */
static int ParseZipArchive(ZipArchive* archive) {
  int result = -1;
  const uint8_t* cd_ptr = (const uint8_t*) archive->directory_map.addr;
  size_t cd_length = archive->directory_map.length;
  int num_entries = archive->num_entries;

  /*
   * Create hash table.  We have a minimum 75% load factor, possibly as
   * low as 50% after we round off to a power of 2.  There must be at
   * least one unused entry to avoid an infinite loop during creation.
   */
  archive->hash_table_size = RoundUpPower2(1 + (num_entries * 4) / 3);
  archive->hash_table = (ZipEntryName*) calloc(archive->hash_table_size,
      sizeof(ZipEntryName));

  /*
   * Walk through the central directory, adding entries to the hash
   * table and verifying values.
   */
  const uint8_t* ptr = cd_ptr;
  int i;
  for (i = 0; i < num_entries; i++) {
    if (get4LE(ptr) != kCDESignature) {
      ALOGW("Zip: missed a central dir sig (at %d)", i);
      goto bail;
    }
    if (ptr + kCDELen > cd_ptr + cd_length) {
      ALOGW("Zip: ran off the end (at %d)", i);
      goto bail;
    }

    const off_t local_header_offset = get4LE(ptr + kCDELocalOffset);
    if (local_header_offset >= archive->directory_offset) {
      ALOGW("Zip: bad LFH offset %ld at entry %d", local_header_offset, i);
      goto bail;
    }

    const uint16_t file_name_length = get2LE(ptr + kCDENameLen);
    const uint16_t extra_length = get2LE(ptr + kCDEExtraLen);
    const uint16_t comment_length = get2LE(ptr + kCDECommentLen);

    /* add the CDE filename to the hash table */
    const int add_result = AddToHash(archive->hash_table,
        archive->hash_table_size, (const char*) ptr + kCDELen, file_name_length);
    if (add_result) {
      ALOGW("Zip: Error adding entry to hash table %d", add_result);
      result = add_result;
      goto bail;
    }

    ptr += kCDELen + file_name_length + extra_length + comment_length;
    if ((size_t)(ptr - cd_ptr) > cd_length) {
      ALOGW("Zip: bad CD advance (%d vs %zd) at entry %d",
        (int) (ptr - cd_ptr), cd_length, i);
      goto bail;
    }
  }
  ALOGV("+++ zip good scan %d entries", num_entries);

  result = 0;

bail:
  return result;
}

/*
 * Prepare to access a ZipArchive through an open file descriptor.
 *
 * On success, we fill out the contents of "archive" and return 0.
 */
int OpenArchiveFd(int fd, const char* debug_file_name,
                  ZipArchiveHandle* handle) {
  int result = -1;
  ZipArchive* archive = (ZipArchive*) malloc(sizeof(ZipArchive));
  *handle = archive;

  memset(archive, 0, sizeof(*archive));
  archive->fd = fd;

  if ((result = MapCentralDirectory(fd, debug_file_name, archive)) != 0) {
    goto bail;
  }

  if ((result = ParseZipArchive(archive)) != 0) {
    ALOGV("Zip: parsing '%s' failed", debug_file_name);
    goto bail;
  }

  /* success */
  result = 0;

bail:
  if (result != 0)
    CloseArchive(handle);
  return result;
}

/*
 * Open the specified file read-only.  We examine the contents and verify
 * that it appears to be a valid zip file.
 *
 * This will be called on non-Zip files, especially during VM startup, so
 * we don't want to be too noisy about certain types of failure.  (Do
 * we want a "quiet" flag?)
 *
 * On success, we fill out the contents of "archive" and return 0.  On
 * failure we return the errno value.
 */
int OpenArchive(const char* fileName, ZipArchiveHandle* handle) {
  int fd, err;

  ALOGV("Opening as zip '%s'", fileName);

  fd = open(fileName, O_RDONLY | O_BINARY, 0);
  if (fd < 0) {
    err = errno ? errno : -1;
    ALOGV("Unable to open '%s': %s", fileName, strerror(err));
    return err;
  }

  return OpenArchiveFd(fd, fileName, handle);
}

/*
 * Close a ZipArchive, closing the file and freeing the contents.
 *
 * NOTE: the ZipArchive may not have been fully created.
 */
void CloseArchive(ZipArchiveHandle* handle) {
  ZipArchive* archive = (ZipArchive*) (*handle);
  ALOGV("Closing archive %p", archive);

  if (archive->fd >= 0) {
    close(archive->fd);
  }

  ReleaseMappedSegment(&archive->directory_map);
  free(archive->hash_table);

  /* ensure nobody tries to use the ZipArchive after it's closed */
  archive->directory_offset = -1;
  archive->fd = -1;
  archive->num_entries = -1;
  archive->hash_table_size = -1;
  archive->hash_table = NULL;

  free(archive);
  *handle = NULL;
}

int VerifyCrcAndLengths(const ZipArchive* archive,
            ZipEntry *entry, const uint32_t compressed_length,
            const uint32_t uncompressed_length, const uint32_t crc32) {
  if (entry->offset == 0) {
    ALOGV("Zip: invalid entry with offset 0");
    return -1;
  }

  if (entry->has_data_descriptor) {
    off_t ddOffset = entry->offset + compressed_length;
    if (lseek(archive->fd, ddOffset, SEEK_SET) != ddOffset) {
      ALOGW("Zip: failed seeking to dd at offset %ld", ddOffset);
      return -1;
    }

    uint8_t ddBuf[kDDMaxLen];
    ssize_t actual = TEMP_FAILURE_RETRY(read(archive->fd, ddBuf, sizeof(ddBuf)));
    if (actual != sizeof(ddBuf)) {
      ALOGW("Zip: failed reading lfh from offset %ld", ddOffset);
      return -1;
    }

    const uint32_t ddSignature = get4LE(ddBuf);
    if (ddSignature == kDDOptSignature) {
      ddOffset += 4;
    }

    if (ddOffset + kDDLen >= archive->directory_offset) {
      ALOGW("Zip: Invalid dd offset");
      return -1;
    }
    entry->crc32 = get4LE(ddBuf + kDDCrc32);
    entry->compressed_length = get4LE(ddBuf + kDDCompLen);
    entry->uncompressed_length = get4LE(ddBuf + kDDUncompLen);
  }

  if (entry->compressed_length == compressed_length && entry->uncompressed_length == uncompressed_length
    && entry->crc32 == crc32) {
    return 0;
  }

  ALOGW("Zip: size/crc32 mismatch. expected {%d, %d, %x}, was {%d, %d, %x}",
      entry->compressed_length, entry->uncompressed_length, entry->crc32,
      compressed_length, uncompressed_length, crc32);

  return -1;
}


static int FindEntry(const ZipArchive* archive, const int ent,
           ZipEntry* data) {
  const uint16_t nameLen = archive->hash_table[ent].name_length;
  const char* name = archive->hash_table[ent].name;

  // Recover the start of the central directory entry from the filename
  // pointer.  The filename is the first entry past the fixed-size data,
  // so we can just subtract back from that.
  const unsigned char* ptr = (const unsigned char*) name;
  ptr -= kCDELen;

  // This is the base of our mmapped region, we have to sanity check that
  // the name that's in the hash table is a pointer to a location within
  // this mapped region.
  const unsigned char* base_ptr = (const unsigned char*)
    archive->directory_map.addr;
  if (ptr < base_ptr || ptr > base_ptr + archive->directory_map.length) {
    ALOGW("Zip: Invalid entry pointer");
    return -1;
  }

  // The offset of the start of the central directory in the zipfile.
  // We keep this lying around so that we can sanity check all our lengths
  // and our per-file structures.
  const off_t cd_offset = archive->directory_offset;

  // Fill out the compression method, modification time, crc32
  // and other interesting attributes from the central directory. These
  // will later be compared against values from the local file header.
  data->method = get2LE(ptr + kCDEMethod);
  data->mod_time = get4LE(ptr + kCDEModWhen);
  data->crc32 = get4LE(ptr + kCDECRC);
  data->compressed_length = get4LE(ptr + kCDECompLen);
  data->uncompressed_length = get4LE(ptr + kCDEUncompressed_length);

  // Figure out the local header offset from the central directory. The
  // actual file data will begin after the local header and the name /
  // extra comments.
  const off_t local_header_offset = get4LE(ptr + kCDELocalOffset);
  if (local_header_offset + kLFHLen >= cd_offset) {
    ALOGW("Zip: bad local hdr offset in zip");
    return -1;
  }

  uint8_t lfh_buf[kLFHLen];
  if (lseek(archive->fd, local_header_offset, SEEK_SET) != local_header_offset) {
    ALOGW("Zip: failed seeking to lfh at offset %ld", local_header_offset);
    return -1;
  }

  ssize_t actual = TEMP_FAILURE_RETRY(read(archive->fd, lfh_buf, sizeof(lfh_buf)));
  if (actual != sizeof(lfh_buf)) {
    ALOGW("Zip: failed reading lfh name from offset %ld", local_header_offset);
    return -1;
  }

  if (get4LE(lfh_buf) != kLFHSignature) {
    ALOGW("Zip: didn't find signature at start of lfh, offset=%ld",
        local_header_offset);
    return -1;
  }

  // Paranoia: Match the values specified in the local file header
  // to those specified in the central directory.
  const uint16_t lfhGpbFlags = get2LE(lfh_buf + kLFHGPBFlags);
  const uint16_t lfhNameLen = get2LE(lfh_buf + kLFHNameLen);
  const uint16_t lfhExtraLen = get2LE(lfh_buf + kLFHExtraLen);

  if ((lfhGpbFlags & kGPBDDFlagMask) == 0) {
    const uint32_t lfhCrc = get2LE(lfh_buf + kLFHCRC);
    const uint32_t lfhCompLen = get2LE(lfh_buf + kLFHCompLen);
    const uint32_t lfhUncompLen = get2LE(lfh_buf + kLFHUncompLen);

    data->has_data_descriptor = 0;
    if (data->compressed_length != lfhCompLen || data->uncompressed_length != lfhUncompLen
      || data->crc32 != lfhCrc) {
      ALOGW("Zip: size/crc32 mismatch. expected {%d, %d, %x}, was {%d, %d, %x}",
        data->compressed_length, data->uncompressed_length, data->crc32,
        lfhCompLen, lfhUncompLen, lfhCrc);
      return -1;
    }
  } else {
    data->has_data_descriptor = 1;
  }

  // Check that the local file header name matches the declared
  // name in the central directory.
  if (lfhNameLen == nameLen) {
    const off_t name_offset = local_header_offset + kLFHLen;
    if (name_offset + lfhNameLen >= cd_offset) {
      ALOGW("Zip: bad name in local hdr");
      return -1;
    }

    if (lseek(archive->fd, name_offset, SEEK_SET) != name_offset) {
      ALOGW("Zip: failed seeking to lfh at offset %ld", name_offset);
      return -1;
    }

    uint8_t* name_buf = (uint8_t*) malloc(nameLen);
    ssize_t actual = TEMP_FAILURE_RETRY(read(archive->fd, name_buf, nameLen));

    if (actual != nameLen || memcmp(name, name_buf, nameLen) != 0) {
      ALOGW("Zip: failed reading lfh name from offset %ld", name_offset);
      free(name_buf);
      return -1;
    }

    free(name_buf);
  } else {
    ALOGW("Zip: lfh name did not match central directory.");
    return -1;
  }

  off_t data_offset = local_header_offset + kLFHLen + lfhNameLen + lfhExtraLen;
  if (data_offset >= cd_offset) {
    ALOGW("Zip: bad data offset %ld in zip", (off_t) data_offset);
    return -1;
  }

  if ((off_t)(data_offset + data->compressed_length) > cd_offset) {
    ALOGW("Zip: bad compressed length in zip (%ld + %zd > %ld)",
      data_offset, data->compressed_length, cd_offset);
    return -1;
  }

  if (data->method == kCompressStored &&
    (off_t)(data_offset + data->uncompressed_length) > cd_offset) {
     ALOGW("Zip: bad uncompressed length in zip (%ld + %zd > %ld)",
       data_offset, data->uncompressed_length, cd_offset);
     return -1;
  }

  data->offset = data_offset;
  return 0;
}

int StartIteration(ZipArchiveHandle handle, uint32_t* cookie) {
  ZipArchive* archive = (ZipArchive *) handle;

  if (archive == NULL || archive->hash_table == NULL) {
    ALOGW("Zip: Invalid ZipArchiveHandle");
    return -1;
  }

  *cookie = 0;
  return 0;
}

int FindEntry(const ZipArchiveHandle handle, const char* entryName,
        ZipEntry* data) {
  const ZipArchive* archive = (ZipArchive*) handle;
  const int nameLen = strlen(entryName);
  if (nameLen == 0 || nameLen > 65535) {
    ALOGW("Zip: Invalid filename %s", entryName);
    return -1;
  }

  const int64_t ent = EntryToIndex(archive->hash_table,
    archive->hash_table_size, entryName, nameLen);

  if (ent < 0) {
    ALOGW("Zip: Could not find entry %.*s", nameLen, entryName);
    return -1;
  }

  return FindEntry(archive, ent, data);
}

int Next(ZipArchiveHandle handle, uint32_t* cookie, ZipEntry* data, ZipEntryName* name) {
  ZipArchive* archive = (ZipArchive *) handle;

  if (archive == NULL || archive->hash_table == NULL) {
    ALOGW("Zip: Invalid ZipArchiveHandle");
    return -1;
  }

  const uint32_t currentOffset = *cookie;
  const uint32_t hash_table_length = archive->hash_table_size;
  const ZipEntryName *hash_table = archive->hash_table;

  for (uint32_t i = currentOffset; i < hash_table_length; ++i) {
    if (hash_table[i].name != NULL) {
      *cookie = (i + 1);
      const int error = FindEntry(archive, i, data);
      if (!error) {
        name->name = hash_table[i].name;
        name->name_length = hash_table[i].name_length;
      }

      return error;
    }
  }

  *cookie = 0;
  return -1;
}



/*
 * Uncompress "deflate" data from the archive's file to an open file
 * descriptor.
 */
static int InflateToFile(int output_fd, int fd, size_t uncompressed_length, size_t compressed_length) {
  int result = -1;
  const size_t kBufSize = 32768;
  unsigned char* read_buf = (unsigned char*) malloc(kBufSize);
  unsigned char* write_buf = (unsigned char*) malloc(kBufSize);
  z_stream zstream;
  int zerr;

  if (read_buf == NULL || write_buf == NULL)
    goto bail;

  /*
   * Initialize the zlib stream struct.
   */
  memset(&zstream, 0, sizeof(zstream));
  zstream.zalloc = Z_NULL;
  zstream.zfree = Z_NULL;
  zstream.opaque = Z_NULL;
  zstream.next_in = NULL;
  zstream.avail_in = 0;
  zstream.next_out = (Bytef*) write_buf;
  zstream.avail_out = kBufSize;
  zstream.data_type = Z_UNKNOWN;

  /*
   * Use the undocumented "negative window bits" feature to tell zlib
   * that there's no zlib header waiting for it.
   */
  zerr = inflateInit2(&zstream, -MAX_WBITS);
  if (zerr != Z_OK) {
    if (zerr == Z_VERSION_ERROR) {
      ALOGE("Installed zlib is not compatible with linked version (%s)",
        ZLIB_VERSION);
    } else {
      ALOGW("Call to inflateInit2 failed (zerr=%d)", zerr);
    }
    goto bail;
  }

  /*
   * Loop while we have more to do.
   */
  do {
    /* read as much as we can */
    if (zstream.avail_in == 0) {
      size_t getSize = (compressed_length > kBufSize) ? kBufSize : compressed_length;

      ssize_t actual = TEMP_FAILURE_RETRY(read(fd, read_buf, getSize));
      if (actual != (ssize_t) getSize) {
        ALOGW("Zip: inflate read failed (%d vs %zd)",
          (int)actual, getSize);
        goto z_bail;
      }

      compressed_length -= getSize;

      zstream.next_in = read_buf;
      zstream.avail_in = getSize;
    }

    /* uncompress the data */
    zerr = inflate(&zstream, Z_NO_FLUSH);
    if (zerr != Z_OK && zerr != Z_STREAM_END) {
      ALOGW("Zip: inflate zerr=%d (nIn=%p aIn=%u nOut=%p aOut=%u)",
        zerr, zstream.next_in, zstream.avail_in,
        zstream.next_out, zstream.avail_out);
      goto z_bail;
    }

    /* write when we're full or when we're done */
    if (zstream.avail_out == 0 ||
      (zerr == Z_STREAM_END && zstream.avail_out != kBufSize)) {
      size_t writeSize = zstream.next_out - write_buf;
      if (WriteFully(output_fd, write_buf, writeSize, "Zip inflate") != 0)
        goto z_bail;

      zstream.next_out = write_buf;
      zstream.avail_out = kBufSize;
    }
  } while (zerr == Z_OK);

  assert(zerr == Z_STREAM_END);     /* other errors should've been caught */

  /* paranoia */
  if (zstream.total_out != uncompressed_length) {
    ALOGW("Zip: size mismatch on inflated file (%ld vs %zd)",
      zstream.total_out, uncompressed_length);
    goto z_bail;
  }

  result = 0;

z_bail:
  inflateEnd(&zstream);    /* free up any allocated structures */

bail:
  free(read_buf);
  free(write_buf);
  return result;
}

/*
 * Uncompress an entry, in its entirety, to an open file descriptor.
 *
 * Returns 0 on success, -1 on failure.
 *
 * TODO: this doesn't verify the data's CRC, but probably should (especially
 * for uncompressed data).
 *
 */
int ExtractEntryToFile(const ZipArchive* archive,
             const ZipEntry* entry, int fd) {
  const uint16_t method = entry->method;
  const uint32_t uncompressed_length = entry->uncompressed_length;
  const uint32_t compressed_length = entry->compressed_length;
  off_t data_offset = entry->offset;

  if (lseek(archive->fd, data_offset, SEEK_SET) != data_offset) {
  ALOGW("Zip: lseek to data at %ld failed", (off_t) data_offset);
  return -1;
  }

  if (method == kCompressStored) {
  if (CopyFileToFile(fd, archive->fd, uncompressed_length) != 0) {
    return -1;
  }
  } else {
  if (InflateToFile(fd, archive->fd, uncompressed_length, compressed_length) != 0) {
    return -1;
  }
  }

  return 0;
}

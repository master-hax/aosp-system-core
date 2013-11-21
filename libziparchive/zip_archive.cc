/*
 * Copyright (C) 2008 The Android Open Source Project
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

/*
 * Read-only access to Zip archives, with minimal heap allocation.
 */
#include "zip_archive.h"

#include <zlib.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <JNIHelp.h>        // TEMP_FAILURE_RETRY may or may not be in unistd

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
#define kLFHNameLen         26              // offset to filename length
#define kLFHExtraLen        28              // offset to extra length

#define kCDESignature       0x02014b50
#define kCDELen             46              // excluding variable-len fields
#define kCDEMethod          10              // offset to compression method
#define kCDEModWhen         12              // offset to modification timestamp
#define kCDECRC             16              // offset to entry CRC
#define kCDECompLen         20              // offset to compressed length
#define kCDEUncompLen       24              // offset to uncompressed length
#define kCDENameLen         28              // offset to filename length
#define kCDEExtraLen        30              // offset to extra length
#define kCDECommentLen      32              // offset to comment length
#define kCDELocalOffset     42              // offset to local hdr

/*
 * The values we return for ZipEntry use 0 as an invalid value, so we
 * want to adjust the hash table index by a fixed amount.  Using a large
 * value helps insure that people don't mix & match arguments, e.g. with
 * entry indices.
 */
#define kZipEntryAdj        10000

#ifdef PAGE_SHIFT
#define SYSTEM_PAGE_SIZE        (1<<PAGE_SHIFT)
#else
#define SYSTEM_PAGE_SIZE        4096
#endif



struct ZipEntryName {
  const char* name;
  uint16_t nameLength;
};

struct MemMapping {
    const uint8_t* addr;  // Start of data
    size_t length;  // Length of data

    uint8_t* baseAddr;  // page-aligned base address
    size_t baseLength;  // length of mapping
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
    int mFd;

    /* mapped central directory area */
    off_t mDirectoryOffset;
    MemMapping mDirectoryMap;

    /* number of entries in the Zip archive */
    uint16_t mNumEntries;

    /*
     * We know how many entries are in the Zip archive, so we can have a
     * fixed-size hash table. We define a load factor of 0.75 and overallocat
     * so the maximum number entries can never be higher than
     * ((4 * UINT16_MAX) / 3 + 1) which can safely fit into a uint32_t.
     */
    uint32_t mHashTableSize;
    ZipEntryName* mHashTable;
};

static int MapFileSegment(const int fd, const off_t start, const size_t length,
                      MemMapping *mapping) {
    /* adjust to be page-aligned */
    const int adjust = start % SYSTEM_PAGE_SIZE;
    const off_t actualStart = start - adjust;
    const off_t actualLength = length + adjust;

    void* memPtr = mmap(NULL, actualLength, PROT_READ, MAP_FILE | MAP_SHARED, fd, actualStart);
    if (memPtr == MAP_FAILED) {
        ALOGW("mmap(%d, R, FILE|SHARED, %d, %d) failed: %s",
            (int) actualLength, fd, (int) actualStart, strerror(errno));
        return -1;
    }

    ALOGV("mmap seg (st=%d ln=%d): bp=%p bl=%d ad=%p ln=%d",
        (int) start, (int) length,
        pMap->baseAddr, (int) pMap->baseLength,
        pMap->addr, (int) pMap->length);

    mapping->addr = (uint8_t*) memPtr;
    mapping->length = actualLength;
    mapping->baseAddr = (uint8_t*) memPtr + adjust;
    mapping->baseLength = length;
    return 0;
}

static void ReleaseMappedSegment(MemMapping* pMap) {
    if (pMap->baseAddr == 0 || pMap->baseLength == 0) {
        return;
    }

    if (munmap(pMap->baseAddr, pMap->baseLength) < 0) {
        ALOGW("munmap(%p, %d) failed: %s",
            pMap->baseAddr, (int)pMap->baseLength, strerror(errno));
    } else {
        ALOGV("munmap(%p, %d) succeeded", pMap->baseAddr, pMap->baseLength);
        free(pMap);
    }
}

static int WriteFully(int fd, const void* buf, size_t count, const char* logMsg) {
   while (count != 0) {
        ssize_t actual = TEMP_FAILURE_RETRY(write(fd, buf, count));
        if (actual < 0) {
            int err = errno;
            ALOGE("%s: write failed: %s", logMsg, strerror(err));
            return err;
        } else if (actual != (ssize_t) count) {
            ALOGD("%s: partial write (will retry): (%d of %zd)",
                logMsg, (int) actual, count);
            buf = (const void*) (((const uint8_t*) buf) + actual);
        }
        count -= actual;
    }

    return 0;
}

static int CopyFileToFile(int outFd, int inFd, size_t count) {
     const size_t kBufSize = 32768;
    unsigned char buf[kBufSize];

    while (count != 0) {
        size_t getSize = (count > kBufSize) ? kBufSize : count;

        ssize_t actual = TEMP_FAILURE_RETRY(read(inFd, buf, getSize));
        if (actual != (ssize_t) getSize) {
            ALOGW("sysCopyFileToFile: copy read failed (%d vs %zd)",
                (int) actual, getSize);
            return -1;
        }

        if (WriteFully(outFd, buf, getSize, "sysCopyFileToFile") != 0) {
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
static uint32_t RoundUpPower2(uint32_t val)
{
    val--;
    val |= val >> 1;
    val |= val >> 2;
    val |= val >> 4;
    val |= val >> 8;
    val |= val >> 16;
    val++;

    return val;
}

static uint32_t computeHash(const char* str, uint16_t len) {
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
static int64_t entryToIndex(const ZipEntryName* hashTable, const uint32_t hashTableSize,
                            const char* name, uint16_t length) {
    const uint32_t hash = computeHash(name, length);

    // NOTE: (hashTableSize - 1) is guaranteed to be non-negative.
    uint32_t ent = hash & (hashTableSize - 1);
    while (hashTable[ent].name != NULL) {
        if (hashTable[ent].nameLength == length &&
            memcmp(hashTable[ent].name, name, length) == 0) {
            return ent;
        }

        ent = (ent + 1) & (hashTableSize - 1);
    }

    ALOGV("Zip: Unable to find entry %.*s", nameLength, name);
    return -1;
}

/*
 * Add a new entry to the hash table.
 */
static int addToHash(ZipEntryName *hashTable, const uint64_t hashTableSize,
                     const char* name, uint16_t length) {
    const uint64_t hash = computeHash(name, length);
    uint64_t ent = hash & (hashTableSize - 1);

    /*
     * We over-allocated the table, so we're guaranteed to find an empty slot.
     * Further, we guarantee that the hashtable size is not 0.
     */
    while (hashTable[ent].name != NULL) {
        if (hashTable[ent].nameLength == length &&
            memcmp(hashTable[ent].name, name, length) == 0) {
            // We've found a duplicate entry. We don't accept it
            ALOGW("Zip: Found duplicate entry %.*s", length, name);
            return -1;
        }
        ent = (ent + 1) & (hashTableSize - 1);
    }

    hashTable[ent].name = name;
    hashTable[ent].nameLength = length;
    return 0;
}

/*
 * Get 2 little-endian bytes.
 */
static uint16_t get2LE(unsigned char const* pSrc)
{
    return pSrc[0] | (pSrc[1] << 8);
}

/*
 * Get 4 little-endian bytes.
 */
static uint32_t get4LE(unsigned char const* pSrc)
{
    uint32_t result;

    result = pSrc[0];
    result |= pSrc[1] << 8;
    result |= pSrc[2] << 16;
    result |= pSrc[3] << 24;

    return result;
}

static int mapCentralDirectory0(int fd, const char* debugFileName,
        ZipArchive* pArchive, off_t fileLength, size_t readAmount, uint8_t* scanBuf)
{
    off_t searchStart = fileLength - readAmount;

    if (lseek(fd, searchStart, SEEK_SET) != searchStart) {
        ALOGW("Zip: seek %ld failed: %s", (long) searchStart, strerror(errno));
        return -1;
    }
    ssize_t actual = TEMP_FAILURE_RETRY(read(fd, scanBuf, readAmount));
    if (actual != (ssize_t) readAmount) {
        ALOGW("Zip: read %zd failed: %s", readAmount, strerror(errno));
        return -1;
    }

    /*
     * Scan backward for the EOCD magic.  In an archive without a trailing
     * comment, we'll find it on the first try.  (We may want to consider
     * doing an initial minimal read; if we don't find it, retry with a
     * second read as above.)
     */
    int i;
    for (i = readAmount - kEOCDLen; i >= 0; i--) {
        if (scanBuf[i] == 0x50 && get4LE(&scanBuf[i]) == kEOCDSignature) {
            ALOGV("+++ Found EOCD at buf+%d", i);
            break;
        }
    }
    if (i < 0) {
        ALOGD("Zip: EOCD not found, %s is not zip", debugFileName);
        return -1;
    }

    off_t eocdOffset = searchStart + i;
    const uint8_t* eocdPtr = scanBuf + i;

    assert(eocdOffset < fileLength);

    /*
     * Grab the CD offset and size, and the number of entries in the
     * archive.  Verify that they look reasonable.
     */
    uint32_t numEntries = get2LE(eocdPtr + kEOCDNumEntries);
    uint32_t dirSize = get4LE(eocdPtr + kEOCDSize);
    uint32_t dirOffset = get4LE(eocdPtr + kEOCDFileOffset);

    if ((long long) dirOffset + (long long) dirSize > (long long) eocdOffset) {
        ALOGW("Zip: bad offsets (dir %ld, size %u, eocd %ld)",
            (long) dirOffset, dirSize, (long) eocdOffset);
        return -1;
    }
    if (numEntries == 0) {
        ALOGW("Zip: empty archive?");
        return -1;
    }

    ALOGV("+++ numEntries=%d dirSize=%d dirOffset=%d",
        numEntries, dirSize, dirOffset);

    /*
     * It all looks good.  Create a mapping for the CD, and set the fields
     * in pArchive.
     */
    const int result = MapFileSegment(fd, dirOffset, dirSize,
                                      &(pArchive->mDirectoryMap));
    if (!result) {
        ALOGW("Zip: cd map failed with return code %d", result);
        return result;
    }

    pArchive->mNumEntries = numEntries;
    pArchive->mDirectoryOffset = dirOffset;

    return 0;
}

/*
 * Find the zip Central Directory and memory-map it.
 *
 * On success, returns 0 after populating fields from the EOCD area:
 *   mDirectoryOffset
 *   mDirectoryMap
 *   mNumEntries
 */
static int mapCentralDirectory(int fd, const char* debugFileName,
    ZipArchive* pArchive)
{
    /*
     * Get and test file length.
     */
    off_t fileLength = lseek(fd, 0, SEEK_END);
    if (fileLength < kEOCDLen) {
        ALOGV("Zip: length %ld is too small to be zip", (long) fileLength);
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
    size_t readAmount = kMaxEOCDSearch;
    if (fileLength < off_t(readAmount))
        readAmount = fileLength;

    uint8_t* scanBuf = (uint8_t*) malloc(readAmount);
    if (scanBuf == NULL) {
        return -1;
    }

    int result = mapCentralDirectory0(fd, debugFileName, pArchive,
            fileLength, readAmount, scanBuf);

    free(scanBuf);
    return result;
}

/*
 * Parses the Zip archive's Central Directory.  Allocates and populates the
 * hash table.
 *
 * Returns 0 on success.
 */
static int parseZipArchive(ZipArchive* pArchive)
{
    int result = -1;
    const uint8_t* cdPtr = (const uint8_t*)pArchive->mDirectoryMap.addr;
    size_t cdLength = pArchive->mDirectoryMap.length;
    int numEntries = pArchive->mNumEntries;

    /*
     * Create hash table.  We have a minimum 75% load factor, possibly as
     * low as 50% after we round off to a power of 2.  There must be at
     * least one unused entry to avoid an infinite loop during creation.
     */
    pArchive->mHashTableSize = RoundUpPower2(1 + (numEntries * 4) / 3);
    pArchive->mHashTable = (ZipEntryName*) calloc(pArchive->mHashTableSize,
                                                  sizeof(ZipEntryName));

    /*
     * Walk through the central directory, adding entries to the hash
     * table and verifying values.
     */
    const uint8_t* ptr = cdPtr;
    int i;
    for (i = 0; i < numEntries; i++) {
        if (get4LE(ptr) != kCDESignature) {
            ALOGW("Zip: missed a central dir sig (at %d)", i);
            goto bail;
        }
        if (ptr + kCDELen > cdPtr + cdLength) {
            ALOGW("Zip: ran off the end (at %d)", i);
            goto bail;
        }

        long localHdrOffset = (long) get4LE(ptr + kCDELocalOffset);
        if (localHdrOffset >= pArchive->mDirectoryOffset) {
            ALOGW("Zip: bad LFH offset %ld at entry %d", localHdrOffset, i);
            goto bail;
        }

        unsigned int fileNameLen, extraLen, commentLen, hash;
        fileNameLen = get2LE(ptr + kCDENameLen);
        extraLen = get2LE(ptr + kCDEExtraLen);
        commentLen = get2LE(ptr + kCDECommentLen);

        /* add the CDE filename to the hash table */
        const int addResult = addToHash(pArchive->mHashTable, pArchive->mHashTableSize,
                                     (const char*)ptr + kCDELen, fileNameLen);
        if (!addResult) {
            ALOGW("Zip: Error adding entry to hash table %d", addResult);
            result = addResult;
            goto bail;
        }

        ptr += kCDELen + fileNameLen + extraLen + commentLen;
        if ((size_t)(ptr - cdPtr) > cdLength) {
            ALOGW("Zip: bad CD advance (%d vs %zd) at entry %d",
                (int) (ptr - cdPtr), cdLength, i);
            goto bail;
        }
    }
    ALOGV("+++ zip good scan %d entries", numEntries);

    result = 0;

bail:
    return result;
}

/*
 * Prepare to access a ZipArchive through an open file descriptor.
 *
 * On success, we fill out the contents of "pArchive" and return 0.
 */
int PrepArchive(int fd, const char* debugFileName, ZipArchive* pArchive)
{
    int result = -1;

    memset(pArchive, 0, sizeof(*pArchive));
    pArchive->mFd = fd;

    if (mapCentralDirectory(fd, debugFileName, pArchive) != 0)
        goto bail;

    if (parseZipArchive(pArchive) != 0) {
        ALOGV("Zip: parsing '%s' failed", debugFileName);
        goto bail;
    }

    /* success */
    result = 0;

bail:
    if (result != 0)
        CloseArchive(pArchive);
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
 * On success, we fill out the contents of "pArchive" and return 0.  On
 * failure we return the errno value.
 */
int OpenArchive(const char* fileName, ZipArchive* pArchive)
{
    int fd, err;

    ALOGV("Opening as zip '%s' %p", fileName, pArchive);

    memset(pArchive, 0, sizeof(ZipArchive));

    fd = open(fileName, O_RDONLY | O_BINARY, 0);
    if (fd < 0) {
        err = errno ? errno : -1;
        ALOGV("Unable to open '%s': %s", fileName, strerror(err));
        return err;
    }

    return PrepArchive(fd, fileName, pArchive);
}

/*
 * Close a ZipArchive, closing the file and freeing the contents.
 *
 * NOTE: the ZipArchive may not have been fully created.
 */
void CloseArchive(ZipArchive* pArchive)
{
    ALOGV("Closing archive %p", pArchive);

    if (pArchive->mFd >= 0)
        close(pArchive->mFd);

    ReleaseMappedSegment(&pArchive->mDirectoryMap);


    free(pArchive->mHashTable);

    /* ensure nobody tries to use the ZipArchive after it's closed */
    pArchive->mDirectoryOffset = -1;
    pArchive->mFd = -1;
    pArchive->mNumEntries = -1;
    pArchive->mHashTableSize = -1;
    pArchive->mHashTable = NULL;
}


/*
 * Find a matching entry.
 *
 * Returns 0 if not found.
 */
int FindEntry(const ZipArchive* pArchive, const char* entryName,
              ZipEntry* data) {
    const int nameLen = strlen(entryName);
    if (nameLen == 0 || nameLen > 65535) {
        ALOGW("Zip: Invalid filename %s", entryName);
        return -1;
    }

    const int64_t ent = entryToIndex(pArchive->mHashTable,
                                       pArchive->mHashTableSize,
                                       entryName,
                                       nameLen);
    if (ent < 0) {
        ALOGV("Zip: Could not find entry %.*s", nameLen, entryName);
        return -1;
    }

    /*
     * Recover the start of the central directory entry from the filename
     * pointer.  The filename is the first entry past the fixed-size data,
     * so we can just subtract back from that.
     */
    const unsigned char* basePtr = (const unsigned char*)
        pArchive->mDirectoryMap.addr;
    const unsigned char* ptr = (const unsigned char*)
        pArchive->mHashTable[ent].name;
    const off_t cdOffset = pArchive->mDirectoryOffset;

    ptr -= kCDELen;

    data->method = get2LE(ptr + kCDEMethod);
    data->modWhen = get4LE(ptr + kCDEModWhen);
    data->crc32 = get4LE(ptr + kCDECRC);
    data->compLen = get4LE(ptr + kCDECompLen);
    data->uncompLen = get4LE(ptr + kCDEUncompLen);

    const off_t localHdrOffset = get4LE(ptr + kCDELocalOffset);
    if (localHdrOffset + kLFHLen >= cdOffset) {
        ALOGW("Zip: bad local hdr offset in zip");
        return -1;
    }

    uint8_t lfhBuf[kLFHLen];
    if (lseek(pArchive->mFd, localHdrOffset, SEEK_SET) != localHdrOffset) {
        ALOGW("Zip: failed seeking to lfh at offset %ld", localHdrOffset);
        return -1;
    }

    ssize_t actual = TEMP_FAILURE_RETRY(read(pArchive->mFd, lfhBuf, sizeof(lfhBuf)));
    if (actual != sizeof(lfhBuf)) {
        ALOGW("Zip: failed reading lfh from offset %ld", localHdrOffset);
        return -1;
    }

    if (get4LE(lfhBuf) != kLFHSignature) {
        ALOGW("Zip: didn't find signature at start of lfh, offset=%ld",
              localHdrOffset);
        return -1;
    }

    off_t dataOffset = localHdrOffset + kLFHLen
         + get2LE(lfhBuf + kLFHNameLen) + get2LE(lfhBuf + kLFHExtraLen);
    if (dataOffset >= cdOffset) {
        ALOGW("Zip: bad data offset %ld in zip", (long) dataOffset);
        return -1;
    }

    /* check lengths */
    if ((off_t)(dataOffset + data->compLen) > cdOffset) {
        ALOGW("Zip: bad compressed length in zip (%ld + %zd > %ld)",
            (long) dataOffset, data->compLen, (long) cdOffset);
        return -1;
    }

    if (data->method == kCompressStored &&
        (off_t)(dataOffset + data->uncompLen) > cdOffset)
    {
         ALOGW("Zip: bad uncompressed length in zip (%ld + %zd > %ld)",
             (long) dataOffset, data->uncompLen, (long) cdOffset);
         return -1;
    }

    data->offset = dataOffset;
    return 0;
}

/*
 * Uncompress "deflate" data from the archive's file to an open file
 * descriptor.
 */
static int InflateToFile(int outFd, int inFd, size_t uncompLen, size_t compLen)
{
    int result = -1;
    const size_t kBufSize = 32768;
    unsigned char* readBuf = (unsigned char*) malloc(kBufSize);
    unsigned char* writeBuf = (unsigned char*) malloc(kBufSize);
    z_stream zstream;
    int zerr;

    if (readBuf == NULL || writeBuf == NULL)
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
    zstream.next_out = (Bytef*) writeBuf;
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
            size_t getSize = (compLen > kBufSize) ? kBufSize : compLen;

            ssize_t actual = TEMP_FAILURE_RETRY(read(inFd, readBuf, getSize));
            if (actual != (ssize_t) getSize) {
                ALOGW("Zip: inflate read failed (%d vs %zd)",
                    (int)actual, getSize);
                goto z_bail;
            }

            compLen -= getSize;

            zstream.next_in = readBuf;
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
            (zerr == Z_STREAM_END && zstream.avail_out != kBufSize))
        {
            size_t writeSize = zstream.next_out - writeBuf;
            if (WriteFully(outFd, writeBuf, writeSize, "Zip inflate") != 0)
                goto z_bail;

            zstream.next_out = writeBuf;
            zstream.avail_out = kBufSize;
        }
    } while (zerr == Z_OK);

    assert(zerr == Z_STREAM_END);       /* other errors should've been caught */

    /* paranoia */
    if (zstream.total_out != uncompLen) {
        ALOGW("Zip: size mismatch on inflated file (%ld vs %zd)",
            zstream.total_out, uncompLen);
        goto z_bail;
    }

    result = 0;

z_bail:
    inflateEnd(&zstream);        /* free up any allocated structures */

bail:
    free(readBuf);
    free(writeBuf);
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
int ExtractEntryToFile(const ZipArchive* pArchive,
    const ZipEntry* entry, int fd) {
    uint16_t method = entry->method;
    uint32_t uncompLen = entry->uncompLen, compLen = entry->compLen;
    off_t dataOffset = entry->offset;

    if (lseek(pArchive->mFd, dataOffset, SEEK_SET) != dataOffset) {
        ALOGW("Zip: lseek to data at %ld failed", (long) dataOffset);
        return -1;
    }

    if (method == kCompressStored) {
        if (CopyFileToFile(fd, pArchive->mFd, uncompLen) != 0) {
            return -1;
        }
    } else {
        if (InflateToFile(fd, pArchive->mFd, uncompLen, compLen) != 0) {
            return -1;
        }
    }

    return 0;
}

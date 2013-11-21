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

/*
 * Read-only access to Zip archives, with minimal heap allocation.
 */
#ifndef LIBZIPARCHIVE_ZIPARCHIVE_H_
#define LIBZIPARCHIVE_ZIPARCHIVE_H_

#include <sys/types.h>

__BEGIN_DECLS

/* Zip compression methods we support */
enum {
  kCompressStored     = 0,        // no compression
  kCompressDeflated   = 8,        // standard deflate
};

struct ZipEntryName {
  const char* name;
  uint16_t name_length;
};

/*
 * Represents information about a zip entry in a zip file.
 */
struct ZipEntry {
  // Compression method: One of kCompressStored or
  // kCompressDeflated.
  uint16_t method;

  // Modification time. The zipfile format specifies
  // that the first two little endian bytes contain the time
  // and the last two little endian bytes contain the date.
  uint32_t mod_time;

  // 1 if this entry contains a data descriptor segment, 0
  // otherwise.
  uint8_t has_data_descriptor;

  // Crc32 value of this ZipEntry. This information might
  // either be stored in the local file header or in a special
  // Data descriptor footer at the end of the file entry.
  uint32_t crc32;

  // Compressed length of this ZipEntry. Might be present
  // either in the local file header or in the data descriptor
  // footer.
  uint32_t compressed_length;

  // Uncompressed length of this ZipEntry. Might be present
  // either in the local file header or in the data descriptor
  // footer.
  uint32_t uncompressed_length;

  // The offset to the start of data for this ZipEntry.
  off_t offset;
};


typedef void* ZipArchiveHandle;

/*
 * Open a Zip archive, and sets handle to the value of the opaque
 * handle for the file. This handle must be released by calling
 * CloseArchive with this handle.
 *
 * Returns 0 on success, and negative values on failure.
 */
int OpenArchive(const char* fileName, ZipArchiveHandle *handle);

/*
 * Like OpenArchive, but takes a file descriptor open for reading
 * at the start of the file.  The descriptor must be mappable (this does
 * not allow access to a stream).
 *
 * Sets handle to the value of the opaque handle for this file descriptor.
 * This handle must be released by calling CloseArchive with this handle.
 *
 * This function maps and scans the central directory and builds a table
 * of entries for future lookups.
 *
 * "debugFileName" will appear in error messages, but is not otherwise used.
 *
 * Returns 0 on success, and negative values on failure.
 */
int OpenArchiveFd(const int fd, const char* debugFileName,
                  ZipArchiveHandle *handle);

/*
 * Close archive, releasing resources associated with it. This will
 * unmap the central directory of the zipfile and free all internal
 * data structures associated with the file. It is an error to use
 * this handle for any further operations without an intervening
 * call to one of the OpenArchive variants.
 */
void CloseArchive(ZipArchiveHandle* handle);

/*
 * Find an entry in the Zip archive, by name. |entryName| must be a null
 * terminated string, and |data| must point to a writeable memory location.
 *
 * Returns 0 if an entry is found, and populates |data| with information
 * about this entry. Returns negative values otherwise.
 *
 * It's important to note that |data->crc32|, |data->compLen| and
 * |data->uncompLen| might be set to 0 if this file entry contains a
 * data descriptor footer. To verify crc32s and length, a call to
 * VerifyCrcAndLengths must be made after entry data has been processed.
 */
int FindEntry(const ZipArchiveHandle handle, const char* entryName,
              ZipEntry* data);

/*
 * Verifies that the given CRC & length of a ZipEntry (as calculated by
 * code uncompressing or consuming the data of an entry) matches those
 * stored in the local file header.(Or data descriptor, as the case may
 * be.)
 *
 * Returns 0 if all information matches, negative values otherwise.
 */
int VerifyCrcAndLengths(const ZipArchiveHandle handle, ZipEntry* data,
                        const uint32_t compLen, const uint32_t uncompLen,
                        const uint32_t crc32);

/*
 * Start iterating over all entries of a zip file. The order of iteration
 * is not guaranteed to be the same as the order of elements
 * in the central directory but is stable for a given zip file. |cookie|
 * must point to a writeable memory location, and will be set to the value
 * of an opaque cookie which can be used to make one or more calls to
 * Next.
 *
 * Returns 0 on success, and negative values on failure.
 */
int StartIteration(ZipArchiveHandle handle, uint32_t* cookie);

/*
 * Advance to the next element in the zipfile in iteration order.
 *
 * Returns 0 on success, -1 if there are no more elements in this
 * archive and lower negative values on failure.
 */
int Next(ZipArchiveHandle handle, uint32_t* cookie, ZipEntry* data,
         ZipEntryName *name);

/*
 * Uncompress and write an entry to a file descriptor.
 *
 * Returns 0 on success.
 */
int ExtractEntryToFile(ZipArchiveHandle handle, ZipEntry* entry, int fd);

__END_DECLS

#endif  // LIBZIPARCHIVE_ZIPARCHIVE_H_

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

/* Zip compression methods we support */
enum {
    kCompressStored     = 0,        // no compression
    kCompressDeflated   = 8,        // standard deflate
};

/*
 * Represents the entry name of a zip entry.
 */
struct ZipEntry {
  uint16_t method;
  uint32_t modWhen;
  uint32_t crc32;
  uint32_t compLen;
  uint32_t uncompLen;
  off_t offset;
};


typedef void* ZipArchiveHandle;


/*
 * Open a Zip archive. Returns a ZipArchive populated with
 */
int OpenArchive(const char* fileName, ZipArchiveHandle *handle);

/*
 * Like OpenArchive, but takes a file descriptor open for reading
 * at the start of the file.  The descriptor must be mappable (this does
 * not allow access to a stream).
 *
 * "debugFileName" will appear in error messages, but is not otherwise used.
 */
int OpenArchive(const int fd, const char* debugFileName, ZipArchiveHandle *handle);

/*
 * Close archive, releasing resources associated with it.
 *
 * Depending on the implementation this could unmap pages used by classes
 * stored in a Jar.  This should only be done after unloading classes.
 */
void CloseArchive(const ZipArchiveHandle handle);

/*
 * Find an entry in the Zip archive, by name.
 */
int FindEntry(ZipArchiveHandle handle, char* entryName, ZipEntry* data);

void* StartIteration(ZipArchiveHandle handle);
int NextEntries(void **iterationHandle, const uint16_t num,
                ZipEntry* data);
void EndIteration(void *iterationHandle);

/*
 * Uncompress and write an entry to a file descriptor.
 *
 * Returns 0 on success.
 */
int ExtractEntryToFile(ZipArchiveHandle handle, ZipEntry* entry, int fd);

#endif  // LIBZIPARCHIVE_ZIPARCHIVE_H_

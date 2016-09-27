/*
 * Copyright (C) 2006 The Android Open Source Project
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

//
// Shared file mapping class.
//

#define LOG_TAG "filemap"

#include <utils/FileMap.h>
#include <utils/Log.h>

#if defined(__MINGW32__) && !defined(__USE_MINGW_ANSI_STDIO)
# define PRId32 "I32d"
# define PRIx32 "I32x"
# define PRId64 "I64d"
#else
#include <inttypes.h>
#endif
#include <stdio.h>
#include <stdlib.h>

#if !defined(__MINGW32__)
#include <sys/mman.h>
#endif

#include <string.h>
#include <memory.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>

#include <string>
#include <vector>

#if !defined(__MINGW32__)
#include <android-base/file.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#endif

using namespace android;

/*static*/ long FileMap::mPageSize = -1;

// Constructor.  Create an empty object.
FileMap::FileMap(void)
    : mFileName(NULL), mBasePtr(NULL), mBaseLength(0),
      mDataPtr(NULL), mDataLength(0)
{
}

// Move Constructor.
FileMap::FileMap(FileMap&& other)
    : mFileName(other.mFileName), mBasePtr(other.mBasePtr), mBaseLength(other.mBaseLength),
      mDataOffset(other.mDataOffset), mDataPtr(other.mDataPtr), mDataLength(other.mDataLength)
#if defined(__MINGW32__)
      , mFileHandle(other.mFileHandle), mFileMapping(other.mFileMapping)
#endif
{
    other.mFileName = NULL;
    other.mBasePtr = NULL;
    other.mDataPtr = NULL;
#if defined(__MINGW32__)
    other.mFileHandle = 0;
    other.mFileMapping = 0;
#endif
}

// Move assign operator.
FileMap& FileMap::operator=(FileMap&& other) {
    mFileName = other.mFileName;
    mBasePtr = other.mBasePtr;
    mBaseLength = other.mBaseLength;
    mDataOffset = other.mDataOffset;
    mDataPtr = other.mDataPtr;
    mDataLength = other.mDataLength;
    other.mFileName = NULL;
    other.mBasePtr = NULL;
    other.mDataPtr = NULL;
#if defined(__MINGW32__)
    mFileHandle = other.mFileHandle;
    mFileMapping = other.mFileMapping;
    other.mFileHandle = 0;
    other.mFileMapping = 0;
#endif
    return *this;
}

// Destructor.
FileMap::~FileMap(void)
{
    if (mFileName != NULL) {
        free(mFileName);
    }
#if defined(__MINGW32__)
    if (mBasePtr && UnmapViewOfFile(mBasePtr) == 0) {
        ALOGD("UnmapViewOfFile(%p) failed, error = %lu\n", mBasePtr,
              GetLastError() );
    }
    if (mFileMapping != INVALID_HANDLE_VALUE) {
        CloseHandle(mFileMapping);
    }
#else
    if (mBasePtr && munmap(mBasePtr, mBaseLength) != 0) {
        ALOGD("munmap(%p, %zu) failed\n", mBasePtr, mBaseLength);
    }
#endif
}


// Create a new mapping on an open file.
//
// Closing the file descriptor does not unmap the pages, so we don't
// claim ownership of the fd.
//
// Returns "false" on failure.
bool FileMap::create(const char* origFileName, int fd, off64_t offset, size_t length,
        bool readOnly)
{
#if defined(__MINGW32__)
    int     adjust;
    off64_t adjOffset;
    size_t  adjLength;

    if (mPageSize == -1) {
        SYSTEM_INFO  si;

        GetSystemInfo( &si );
        mPageSize = si.dwAllocationGranularity;
    }

    DWORD  protect = readOnly ? PAGE_READONLY : PAGE_READWRITE;

    mFileHandle  = (HANDLE) _get_osfhandle(fd);
    mFileMapping = CreateFileMapping( mFileHandle, NULL, protect, 0, 0, NULL);
    if (mFileMapping == NULL) {
        ALOGE("CreateFileMapping(%p, %lx) failed with error %lu\n",
              mFileHandle, protect, GetLastError() );
        return false;
    }

    adjust    = offset % mPageSize;
    adjOffset = offset - adjust;
    adjLength = length + adjust;

    mBasePtr = MapViewOfFile( mFileMapping,
                              readOnly ? FILE_MAP_READ : FILE_MAP_ALL_ACCESS,
                              0,
                              (DWORD)(adjOffset),
                              adjLength );
    if (mBasePtr == NULL) {
        ALOGE("MapViewOfFile(%" PRId64 ", %zu) failed with error %lu\n",
              adjOffset, adjLength, GetLastError() );
        CloseHandle(mFileMapping);
        mFileMapping = INVALID_HANDLE_VALUE;
        return false;
    }
#else // !defined(__MINGW32__)
    int     prot, flags, adjust;
    off64_t adjOffset;
    size_t  adjLength;

    void* ptr;

    assert(fd >= 0);
    assert(offset >= 0);
    assert(length > 0);

    // init on first use
    if (mPageSize == -1) {
        mPageSize = sysconf(_SC_PAGESIZE);
        if (mPageSize == -1) {
            ALOGE("could not get _SC_PAGESIZE\n");
            return false;
        }
    }

    adjust = offset % mPageSize;
    adjOffset = offset - adjust;
    adjLength = length + adjust;

    flags = MAP_SHARED;
    prot = PROT_READ;
    if (!readOnly)
        prot |= PROT_WRITE;

    ptr = mmap(NULL, adjLength, prot, flags, fd, adjOffset);
    if (ptr == MAP_FAILED) {
        ALOGE("mmap(%lld,%zu) failed: %s\n",
            (long long)adjOffset, adjLength, strerror(errno));
        return false;
    }
    mBasePtr = ptr;
#endif // !defined(__MINGW32__)

    mFileName = origFileName != NULL ? strdup(origFileName) : NULL;
    mBaseLength = adjLength;
    mDataOffset = offset;
    mDataPtr = (char*) mBasePtr + adjust;
    mDataLength = length;

    assert(mBasePtr != NULL);

    ALOGV("MAP: base %p/%zu data %p/%zu\n",
        mBasePtr, mBaseLength, mDataPtr, mDataLength);

    return true;
}

#if !defined(__MINGW32__)
bool FileMap::createSubset(const FileMap* file_map, off64_t offset, size_t length) {
    //Create a memory mapped region from a mapped address
    assert(offset >= 0);
    assert(length > 0);
    assert(file_map->mBasePtr != NULL);

    if (mPageSize == -1) {
        mPageSize = sysconf(_SC_PAGESIZE);
        if (mPageSize == -1) {
            ALOGE("could not get _SC_PAGESIZE\n");
            return false;
        }
    }
    assert(mPageSize == file_map->mPageSize);

    mBasePtr = file_map->mBasePtr;
    mBaseLength = file_map->mBaseLength;
    mDataOffset = offset;
    mDataPtr = (char*) mBasePtr + offset;
    mDataLength = length;

    return true;
}

bool FileMap::createFromBlockFile(const char* blockFile) {
  std::string blockMap;
  if (!android::base::ReadFileToString(blockFile, &blockMap)) {
    ALOGE("failed to read blockmap: %s\n", blockFile);
    return false;
  }

  std::vector<std::string> lines = android::base::Split(android::base::Trim(blockMap), "\n");

  if (lines.size() < 4) {
    ALOGE("too few lines in blockMap: %zu\n", lines.size());
    return false;
  }

  std::string blockDev = android::base::Trim(lines[0]);
  size_t totalSize;
  unsigned int blockSize;
  if (sscanf(android::base::Trim(lines[1]).c_str(), "%zu %u", &totalSize, &blockSize) != 2) {
    ALOGE("failed to read total size in: %s \n", lines[1].c_str());
    return false;
  }
  size_t rangeCount;
  if (sscanf(android::base::Trim(lines[2]).c_str(), "%zu", &rangeCount) != 1) {
    ALOGE("failed to read range counts in: %s\n", lines[2].c_str());
    return false;
  }
  assert (rangeCount == lines.size() - 3);

  size_t blocks = 0;
  if (blockSize != 0) {
    blocks = ((totalSize-1) / blockSize) + 1;
  }

  if (totalSize == 0 || blockSize == 0 || blocks > SIZE_MAX / blockSize || rangeCount == 0) {
    ALOGE("invalid data in block map file: totalSize %zu, blockSize %u, rangeCount %zu\n",
           totalSize, blockSize, rangeCount);
  }

  uint8_t* reserve = reinterpret_cast<uint8_t*>(mmap64(NULL, blocks * blockSize,
            PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0));

  if (reserve == MAP_FAILED) {
    ALOGE("failed to reserve address space\n");
  }

  android::base::unique_fd fd(open(blockDev.c_str(), O_RDONLY));
  if(fd == -1) {
    ALOGE("failed to open block_dev %s, error: %s\n", blockDev.c_str(), strerror(errno));
    munmap(reserve, blocks * blockSize);
  }

  uint8_t* next = reserve;
  size_t remaining = blocks * blockSize;
  bool success = true;
  for (size_t i = 3; i < lines.size(); i++) {
    size_t start, end;
    if (sscanf(lines[i].c_str(), "%zu %zu", &start, &end) != 2) {
      ALOGE("failed to parse range %s\n", lines[i].c_str());
      success = false;
      break;
    }

    size_t length = (end - start) * blockSize;
    if (end <= start || (end - start) > SIZE_MAX || length > remaining) {
      ALOGE("unexpected range in block map: %zu, %zu", start, end);
      success = false;
      break;
    }

    void* addr = mmap64(next, length, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, static_cast<off64_t>(start)*blockSize);
    if (addr == MAP_FAILED) {
      success = false;
      break;
    }

    next += length;
    remaining -= length;
  }

  if (!success || remaining != 0) {
    ALOGE("failed to create memory map, remaining size: %zu\n", remaining);
    munmap(reserve, blocks * blockSize);
    return false;
  }

  ALOGI("mapped %zu\n", rangeCount);
  mBasePtr = static_cast<void*>(reserve);
  mBaseLength = blocks * blockSize;
  mDataPtr = static_cast<void*>(reserve);
  mDataOffset = 0;
  mDataLength = totalSize;

  return true;
}
#endif

// Provide guidance to the system.
#if !defined(_WIN32)
int FileMap::advise(MapAdvice advice)
{
    int cc, sysAdvice;

    switch (advice) {
        case NORMAL:        sysAdvice = MADV_NORMAL;        break;
        case RANDOM:        sysAdvice = MADV_RANDOM;        break;
        case SEQUENTIAL:    sysAdvice = MADV_SEQUENTIAL;    break;
        case WILLNEED:      sysAdvice = MADV_WILLNEED;      break;
        case DONTNEED:      sysAdvice = MADV_DONTNEED;      break;
        default:
                            assert(false);
                            return -1;
    }

    cc = madvise(mBasePtr, mBaseLength, sysAdvice);
    if (cc != 0)
        ALOGW("madvise(%d) failed: %s\n", sysAdvice, strerror(errno));
    return cc;
}

#else
int FileMap::advise(MapAdvice /* advice */)
{
    return -1;
}
#endif

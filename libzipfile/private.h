#ifndef PRIVATE_H
#define PRIVATE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <zlib.h>

typedef struct Zipentry {
    unsigned long fileNameLength;
    const unsigned char* fileName;
    unsigned short compressionMethod;
    unsigned int uncompressedSize;
    unsigned int compressedSize;
    const unsigned char* data;

    /* The following twp fields are used when the
     * size of the output buffer is smaller than
     * uncompressed file size.
     */
    unsigned int uncompressedBytes; /* The number of bytes  already inflated */
    z_stream* zstream; /* The zstream object passed to the zlib library */

    struct Zipentry* next;
} Zipentry;

typedef struct Zipfile
{
    const unsigned char *buf;
    ssize_t bufsize;

    /* Central directory */
    unsigned short  disknum;            /* mDiskNumber; */
    unsigned short  diskWithCentralDir; /* mDiskWithCentralDir; */
    unsigned short  entryCount;         /* mNumEntries; */
    unsigned short  totalEntryCount;    /* mTotalNumEntries; */
    unsigned int    centralDirSize;     /* mCentralDirSize; */
    unsigned int    centralDirOffest;   /* offset from first disk  mCentralDirOffset; */
    unsigned short  commentLen;         /* mCommentLen; */
    const unsigned char*  comment;      /* mComment; */

    Zipentry* entries;
} Zipfile;

int read_central_dir(Zipfile* file);

unsigned int read_le_int(const unsigned char* buf);
unsigned int read_le_short(const unsigned char* buf);

#endif /* PRIVATE_H */


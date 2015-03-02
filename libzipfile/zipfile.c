#include <zipfile/zipfile.h>

#include "private.h"
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <math.h>

#define DEF_MEM_LEVEL 8                // normally in zutil.h?

zipfile_t
init_zipfile(const void* data, size_t size)
{
    int err;

    Zipfile *file = malloc(sizeof(Zipfile));
    if (file == NULL) return NULL;
    memset(file, 0, sizeof(Zipfile));
    file->buf = data;
    file->bufsize = size;

    err = read_central_dir(file);
    if (err != 0) goto fail;

    return file;
fail:
    free(file);
    return NULL;
}

void
release_zipfile(zipfile_t f)
{
    Zipfile* file = (Zipfile*)f;
    Zipentry* entry = file->entries;
    while (entry) {
        Zipentry* next = entry->next;
        free(entry);
        entry = next;
    }
    free(file);
}

zipentry_t
lookup_zipentry(zipfile_t f, const char* entryName)
{
    Zipfile* file = (Zipfile*)f;
    Zipentry* entry = file->entries;
    while (entry) {
        if (0 == memcmp(entryName, entry->fileName, entry->fileNameLength)) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

size_t
get_zipentry_size(zipentry_t entry)
{
    return ((Zipentry*)entry)->uncompressedSize;
}

char*
get_zipentry_name(zipentry_t entry)
{
    Zipentry* e = (Zipentry*)entry;
    int l = e->fileNameLength;
    char* s = malloc(l+1);
    memcpy(s, e->fileName, l);
    s[l] = '\0';
    return s;
}

enum {
    STORED = 0,
    DEFLATED = 8
};

static int
uninflate(unsigned char* out, int unlen, const unsigned char* in, int clen)
{
    z_stream zstream;
    int err = END_OF_STREAM;
    int zerr;

    memset(&zstream, 0, sizeof(zstream));
    zstream.zalloc = Z_NULL;
    zstream.zfree = Z_NULL;
    zstream.opaque = Z_NULL;
    zstream.next_in = (void*)in;
    zstream.avail_in = clen;
    zstream.next_out = (Bytef*) out;
    zstream.avail_out = unlen;
    zstream.data_type = Z_UNKNOWN;

    /* Use the undocumented "negative window bits" feature to tell zlib
     * that there's no zlib header waiting for it.
     */
    zerr = inflateInit2(&zstream, -MAX_WBITS);
    if (zerr != Z_OK) {
        return UNZIP_ERROR;
    }

    /* uncompress the data */
    zerr = inflate(&zstream, Z_FINISH);
    if (zerr != Z_STREAM_END) {
        fprintf(stderr, "zerr=%d Z_STREAM_END=%d total_out=%lu\n", zerr, Z_STREAM_END,
                    zstream.total_out);
        err = UNZIP_ERROR;
    }

     inflateEnd(&zstream);
    return err;
}

int
decompress_zipentry(zipentry_t e, void* buf, int bufsize)
{
    Zipentry* entry = (Zipentry*)e;
    switch (entry->compressionMethod)
    {
        case STORED:
            memcpy(buf, entry->data, entry->uncompressedSize);
            return 0;
        case DEFLATED:
            return uninflate(buf, bufsize, entry->data, entry->compressedSize);
        default:
            return -1;
    }
}

/* call this api instead of decompress_zipentry if the size of the buffer
 * passed is smaller than the uncompressed size of the image.
 * The caller should repeat calling the function until the function
 * returns END_OF_STREAM or UNZIP_ERROR. The function returns
 * BUFFER_FULL when there is more uncompressed data left in the input
 * file, but the zip engine has run out of output buffer space.
 */

int
decompress_zipentry_multiple(zipentry_t e, void* buf, unsigned int bufsize, unsigned int* bytescopied)
{
    Zipentry* entry = (Zipentry*)e;
    int err = END_OF_STREAM;
    int zerr;

    if ( entry == NULL || buf == NULL || bytescopied == NULL) {
        fprintf(stderr, "Null pointers passed in one of the arguments\n");
        return UNZIP_ERROR;
    }

    /* if we have enough space in the output buffer to
     * hold the entire decompressed output, then, call
     * into decompress_zipentry.
     */

    if (bufsize > ceil(entry->uncompressedSize * 1.001)) {
        *bytescopied = get_zipentry_size(e);
        return decompress_zipentry(e, buf, bufsize);
    }

    switch (entry->compressionMethod)
    {
        case STORED:
            if (bufsize >= (entry->uncompressedSize - entry->uncompressedBytes)) {
                memcpy(buf, entry->data + entry->uncompressedBytes,
                    entry->uncompressedSize - entry->uncompressedBytes);
                *bytescopied = entry->uncompressedSize - entry->uncompressedBytes;
                return END_OF_STREAM;
            } else {
                memcpy(buf, entry->data + entry->uncompressedBytes, bufsize);
                entry->uncompressedBytes += bufsize;
                *bytescopied = bufsize;
                return BUFFER_FULL;
            }
        case DEFLATED:
        /* zstream initialized during the first call to decompress a file. */
            if(entry->zstream == NULL) {
                entry->zstream = calloc(1, sizeof(z_stream));
                if(entry->zstream == NULL) {
                    fprintf(stderr, "failed to allocate %lu bytes\n",
                        (unsigned long)sizeof(z_stream));
                    return UNZIP_ERROR;
                }

                entry->zstream->zalloc = Z_NULL;
                entry->zstream->zfree = Z_NULL;
                entry->zstream->opaque = Z_NULL;
                entry->zstream->next_in = (void*)entry->data;
                entry->zstream->avail_in = entry->compressedSize;
                entry->zstream->next_out = (Bytef*)buf;
                entry->zstream->avail_out = bufsize;
                entry->zstream->data_type = Z_UNKNOWN;

                zerr = inflateInit2(entry->zstream, -MAX_WBITS);
                if (zerr != Z_OK) {
                    return UNZIP_ERROR;
                }
            } else {
                entry->zstream->next_out = (Bytef*)buf;
                entry->zstream->avail_out = bufsize;
            }
            /* uncompress the data */
            zerr = inflate(entry->zstream, Z_SYNC_FLUSH);
            if (zerr == Z_OK) {
                *bytescopied = bufsize;
                err = BUFFER_FULL;
            } else if (zerr == Z_STREAM_END) {
                *bytescopied = bufsize - entry->zstream->avail_out;
                inflateEnd(entry->zstream);
                free(entry->zstream);
                entry->zstream = NULL;
                err = END_OF_STREAM;
            } else {
                fprintf(stderr, "zerr=%d Z_STREAM_END=%d total_out=%lu\n",
                    zerr, Z_STREAM_END, entry->zstream->total_out);
                free(entry->zstream);
                entry->zstream = NULL;
                err = UNZIP_ERROR;
            }

            return err;
        default:
            return UNZIP_ERROR;
    }
}


void
dump_zipfile(FILE* to, zipfile_t file)
{
    Zipfile* zip = (Zipfile*)file;
    Zipentry* entry = zip->entries;
    int i;

    fprintf(to, "entryCount=%d\n", zip->entryCount);
    for (i=0; i<zip->entryCount; i++) {
        fprintf(to, "  file \"");
        fwrite(entry->fileName, entry->fileNameLength, 1, to);
        fprintf(to, "\"\n");
        entry = entry->next;
    }
}

zipentry_t
iterate_zipfile(zipfile_t file, void** cookie)
{
    Zipentry* entry = (Zipentry*)*cookie;
    if (entry == NULL) {
        Zipfile* zip = (Zipfile*)file;
        *cookie = zip->entries;
        return *cookie;
    } else {
        entry = entry->next;
        *cookie = entry;
        return entry;
    }
}

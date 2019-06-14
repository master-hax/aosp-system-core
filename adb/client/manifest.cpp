// Copyright 2019 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "manifest.h"

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>

#include <utils/ByteOrder.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/Unicode.h>
#include <ziparchive/zip_archive.h>

#include "adb_utils.h"

using namespace android;

enum {
    RES_STRING_POOL_TYPE = 0x0001,

    // Chunk types in RES_XML_TYPE
    RES_XML_FIRST_CHUNK_TYPE = 0x0100,
    RES_XML_START_NAMESPACE_TYPE = 0x0100,
    RES_XML_END_NAMESPACE_TYPE = 0x0101,
    RES_XML_START_ELEMENT_TYPE = 0x0102,
    RES_XML_END_ELEMENT_TYPE = 0x0103,
    RES_XML_CDATA_TYPE = 0x0104,
    RES_XML_LAST_CHUNK_TYPE = 0x017f,
};

/**
 * Header that appears at the front of every data chunk in a resource.
 */
struct ResChunk_header {
    // Type identifier for this chunk.  The meaning of this value depends
    // on the containing chunk.
    uint16_t type;

    // Size of the chunk header (in bytes).  Adding this value to
    // the address of the chunk allows you to find its associated data
    // (if any).
    uint16_t headerSize;

    // Total size of this chunk (in bytes).  This is the chunkSize plus
    // the size of any data associated with the chunk.  Adding this value
    // to the chunk allows you to completely skip its contents (including
    // any child chunks).  If this value is the same as chunkSize, there is
    // no data associated with the chunk.
    uint32_t size;
};

/**
 * Definition for a pool of strings.  The data of this chunk is an
 * array of uint32_t providing indices into the pool, relative to
 * stringsStart.  At stringsStart are all of the UTF-16 strings
 * concatenated together; each starts with a uint16_t of the string's
 * length and each ends with a 0x0000 terminator.  If a string is >
 * 32767 characters, the high bit of the length is set meaning to take
 * those 15 bits as a high word and it will be followed by another
 * uint16_t containing the low word.
 *
 * If styleCount is not zero, then immediately following the array of
 * uint32_t indices into the string table is another array of indices
 * into a style table starting at stylesStart.  Each entry in the
 * style table is an array of ResStringPool_span structures.
 */
struct ResStringPool_header {
    struct ResChunk_header header;

    // Number of strings in this pool (number of uint32_t indices that follow
    // in the data).
    uint32_t stringCount;

    // Number of style span arrays in the pool (number of uint32_t indices
    // follow the string indices).
    uint32_t styleCount;

    enum {
        // String pool is encoded in UTF-8
        UTF8_FLAG = 1 << 8
    };
    uint32_t flags;

    // Index from header of the string data.
    uint32_t stringsStart;

    // Index from header of the style data.
    uint32_t stylesStart;
};

static status_t validate_chunk(const ResChunk_header* chunk, size_t minSize, const uint8_t* dataEnd,
                               const char* name) {
    const uint16_t headerSize = dtohs(chunk->headerSize);
    const uint32_t size = dtohl(chunk->size);

    if (headerSize >= minSize) {
        if (headerSize <= size) {
            if (((headerSize | size) & 0x3) == 0) {
                if ((size_t)size <= (size_t)(dataEnd - ((const uint8_t*)chunk))) {
                    return NO_ERROR;
                }
                printf("%s data size 0x%x extends beyond resource end %p.", name, size,
                       (void*)(dataEnd - ((const uint8_t*)chunk)));
                return BAD_TYPE;
            }
            printf("%s size 0x%x or headerSize 0x%x is not on an integer boundary.", name,
                   (int)size, (int)headerSize);
            return BAD_TYPE;
        }
        printf("%s size 0x%x is smaller than header size 0x%x.", name, size, headerSize);
        return BAD_TYPE;
    }
    printf("%s header size 0x%04x is too small.", name, headerSize);
    return BAD_TYPE;
}

/**
 * Convenience class for accessing data in a RES_STRING_POOL_TYPE chunk.
 */
class ResStringPool {
  public:
    ResStringPool();
    ~ResStringPool();

    status_t SetTo(const void* data, size_t size);
    status_t GetError() const;
    const std::string StringAt(size_t idx) const;

  private:
    status_t mError;
    const ResStringPool_header* mHeader;
    size_t mSize;
    const uint32_t* mEntries;
    const void* mStrings;
    uint32_t mStringPoolSize;  // number of uint16_t

    const char* StringDecodeAt(size_t idx, const uint8_t* str, const size_t encLen,
                               size_t* outLen) const;
};

ResStringPool::ResStringPool() : mError(NO_INIT), mHeader(NULL) {}

ResStringPool::~ResStringPool() {}

status_t ResStringPool::SetTo(const void* data, size_t size) {
    if (!data || !size) {
        return (mError = BAD_TYPE);
    }

    // The chunk must be at least the size of the string pool header.
    if (size < sizeof(ResStringPool_header)) {
        printf("Bad string block: data size %zu is too small to be a string block", size);
        return (mError = BAD_TYPE);
    }

    // The data is at least as big as a ResChunk_header, so we can safely validate the other
    // header fields.
    // `data + size` is safe because the source of `size` comes from the kernel/filesystem.
    if (validate_chunk(reinterpret_cast<const ResChunk_header*>(data), sizeof(ResStringPool_header),
                       reinterpret_cast<const uint8_t*>(data) + size,
                       "ResStringPool_header") != NO_ERROR) {
        printf("Bad string block: malformed block dimensions");

        return (mError = BAD_TYPE);
    }

    const bool notDeviceEndian = htods(0xf0) != 0xf0;

    // The size has been checked, so it is safe to read the data in the ResStringPool_header
    // data structure.
    mHeader = (const ResStringPool_header*)data;

    if (notDeviceEndian) {
        ResStringPool_header* h = const_cast<ResStringPool_header*>(mHeader);
        h->header.headerSize = dtohs(mHeader->header.headerSize);
        h->header.type = dtohs(mHeader->header.type);
        h->header.size = dtohl(mHeader->header.size);
        h->stringCount = dtohl(mHeader->stringCount);
        h->styleCount = dtohl(mHeader->styleCount);
        h->flags = dtohl(mHeader->flags);
        h->stringsStart = dtohl(mHeader->stringsStart);
        h->stylesStart = dtohl(mHeader->stylesStart);
    }

    if (mHeader->header.headerSize > mHeader->header.size || mHeader->header.size > size) {
        printf("Bad string block: header size %d or total size %d is larger than data size %d\n",
               (int)mHeader->header.headerSize, (int)mHeader->header.size, (int)size);
        return (mError = BAD_TYPE);
    }
    mSize = mHeader->header.size;
    mEntries = (const uint32_t*)(((const uint8_t*)data) + mHeader->header.headerSize);

    if (mHeader->stringCount > 0) {
        if ((mHeader->stringCount * sizeof(uint32_t) < mHeader->stringCount)  // uint32 overflow?
            || (mHeader->header.headerSize + (mHeader->stringCount * sizeof(uint32_t))) > size) {
            printf("Bad string block: entry of %d items extends past data size %d\n",
                   (int)(mHeader->header.headerSize + (mHeader->stringCount * sizeof(uint32_t))),
                   (int)size);
            return (mError = BAD_TYPE);
        }

        size_t charSize;
        if (mHeader->flags & ResStringPool_header::UTF8_FLAG) {
            charSize = sizeof(uint8_t);
        } else {
            charSize = sizeof(uint16_t);
        }

        // There should be at least space for the smallest string
        // (2 bytes length, null terminator).
        if (mHeader->stringsStart >= (mSize - sizeof(uint16_t))) {
            printf("Bad string block: string pool starts at %d, after total size %d\n",
                   (int)mHeader->stringsStart, (int)mHeader->header.size);
            return (mError = BAD_TYPE);
        }

        mStrings = (const void*)(((const uint8_t*)data) + mHeader->stringsStart);

        if (mHeader->styleCount == 0) {
            mStringPoolSize = (mSize - mHeader->stringsStart) / charSize;
        } else {
            // check invariant: styles starts before end of data
            if (mHeader->stylesStart >= (mSize - sizeof(uint16_t))) {
                printf("Bad style block: style block starts at %d past data size of %d\n",
                       (int)mHeader->stylesStart, (int)mHeader->header.size);
                return (mError = BAD_TYPE);
            }
            // check invariant: styles follow the strings
            if (mHeader->stylesStart <= mHeader->stringsStart) {
                printf("Bad style block: style block starts at %d, before strings at %d\n",
                       (int)mHeader->stylesStart, (int)mHeader->stringsStart);
                return (mError = BAD_TYPE);
            }
            mStringPoolSize = (mHeader->stylesStart - mHeader->stringsStart) / charSize;
        }

        // check invariant: stringCount > 0 requires a string pool to exist
        if (mStringPoolSize == 0) {
            printf("Bad string block: stringCount is %d but pool size is 0\n",
                   (int)mHeader->stringCount);
            return (mError = BAD_TYPE);
        }

        if (notDeviceEndian) {
            size_t i;
            uint32_t* e = const_cast<uint32_t*>(mEntries);
            for (i = 0; i < mHeader->stringCount; i++) {
                e[i] = dtohl(mEntries[i]);
            }
            if (!(mHeader->flags & ResStringPool_header::UTF8_FLAG)) {
                const uint16_t* strings = (const uint16_t*)mStrings;
                uint16_t* s = const_cast<uint16_t*>(strings);
                for (i = 0; i < mStringPoolSize; i++) {
                    s[i] = dtohs(strings[i]);
                }
            }
        }

        if ((mHeader->flags & ResStringPool_header::UTF8_FLAG &&
             ((uint8_t*)mStrings)[mStringPoolSize - 1] != 0) ||
            (!(mHeader->flags & ResStringPool_header::UTF8_FLAG) &&
             ((uint16_t*)mStrings)[mStringPoolSize - 1] != 0)) {
            printf("Bad string block: last string is not 0-terminated\n");
            return (mError = BAD_TYPE);
        }
    } else {
        mStrings = NULL;
        mStringPoolSize = 0;
    }

    return (mError = NO_ERROR);
}

status_t ResStringPool::GetError() const {
    return mError;
}

static std::string get_string_from_utf16(const char16_t* input, size_t len) {
    ssize_t utf8_length = utf16_to_utf8_length(input, len);
    if (utf8_length <= 0) {
        return "";
    }

    std::string utf8;
    utf8.resize(utf8_length);
    utf16_to_utf8(input, len, &*utf8.begin(), utf8_length + 1);
    return utf8;
}

/**
 * Strings in UTF-16 format have length indicated by a length encoded in the
 * stored data. It is either 1 or 2 characters of length data. This allows a
 * maximum length of 0x7FFFFFF (2147483647 bytes), but if you're storing that
 * much data in a string, you're abusing them.
 *
 * If the high bit is set, then there are two characters or 4 bytes of length
 * data encoded. In that case, drop the high bit of the first character and
 * add it together with the Next character.
 */
static inline size_t decodeLength16(const uint16_t** str) {
    size_t len = **str;
    if ((len & 0x8000) != 0) {
        (*str)++;
        len = ((len & 0x7FFF) << 16) | **str;
    }
    (*str)++;
    return len;
}

/**
 * Strings in UTF-8 format have length indicated by a length encoded in the
 * stored data. It is either 1 or 2 characters of length data. This allows a
 * maximum length of 0x7FFF (32767 bytes), but you should consider storing
 * text in another way if you're using that much data in a single string.
 *
 * If the high bit is set, then there are two characters or 2 bytes of length
 * data encoded. In that case, drop the high bit of the first character and
 * add it together with the Next character.
 */
static inline size_t decodeLength8(const uint8_t** str) {
    size_t len = **str;
    if ((len & 0x80) != 0) {
        (*str)++;
        len = ((len & 0x7F) << 8) | **str;
    }
    (*str)++;
    return len;
}

const std::string ResStringPool::StringAt(size_t idx) const {
    if (mError == NO_ERROR && idx < mHeader->stringCount) {
        const bool isUTF8 = (mHeader->flags & ResStringPool_header::UTF8_FLAG) != 0;
        const uint32_t off = mEntries[idx] / (isUTF8 ? sizeof(uint8_t) : sizeof(uint16_t));
        if (off < (mStringPoolSize - 1)) {
            if (!isUTF8) {
                const uint16_t* strings = (uint16_t*)mStrings;
                const uint16_t* str = strings + off;

                size_t u16len = decodeLength16(&str);
                if ((uint32_t)(str + u16len - strings) < mStringPoolSize) {
                    // Reject malformed (non null-terminated) strings
                    if (str[u16len] != 0x0000) {
                        printf("Bad string block: string #%d is not null-terminated", (int)idx);
                        return NULL;
                    }

                    return get_string_from_utf16(reinterpret_cast<const char16_t*>(str), u16len);
                } else {
                    printf("Bad string block: string #%d extends to %d, past end at %d\n", (int)idx,
                           (int)(str + u16len - strings), (int)mStringPoolSize);
                }
            } else {
                const uint8_t* strings = (uint8_t*)mStrings;
                const uint8_t* u8str = strings + off;

                size_t u8len = decodeLength8(&u8str);

                // encLen must be less than 0x7FFF due to encoding.
                if ((uint32_t)(u8str + u8len - strings) < mStringPoolSize) {
                    // Retrieve the actual length of the utf8 string if the
                    // encoded length was truncated
                    if (StringDecodeAt(idx, u8str, u8len, &u8len) == NULL) {
                        return NULL;
                    }

                    return std::string(reinterpret_cast<const char*>(u8str), u8len);
                } else {
                    printf("Bad string block: string #%lld extends to %lld, past end at %lld\n",
                           (long long)idx, (long long)(u8str + u8len - strings),
                           (long long)mStringPoolSize);
                }
            }
        } else {
            printf("Bad string block: string #%d entry is at %d, past end at %d\n", (int)idx,
                   (int)(off * sizeof(uint16_t)), (int)(mStringPoolSize * sizeof(uint16_t)));
        }
    }
    return NULL;
}

/**
 * AAPT incorrectly writes a truncated string length when the string size
 * exceeded the maximum possible encode length value (0x7FFF). To decode a
 * truncated length, iterate through length values that end in the encode length
 * bits. Strings that exceed the maximum encode length are not placed into
 * StringPools in AAPT2.
 **/
const char* ResStringPool::StringDecodeAt(size_t idx, const uint8_t* str, const size_t encLen,
                                          size_t* outLen) const {
    const uint8_t* strings = (uint8_t*)mStrings;

    size_t i = 0, end = encLen;
    while ((uint32_t)(str + end - strings) < mStringPoolSize) {
        if (str[end] == 0x00) {
            if (i != 0) {
                printf("Bad string block: string #%d is truncated (actual length is %d)", (int)idx,
                       (int)end);
            }

            *outLen = end;
            return (const char*)str;
        }

        end = (++i << (sizeof(uint8_t) * 8 * 2 - 1)) | encLen;
    }

    // Reject malformed (non null-terminated) strings
    printf("Bad string block: string #%d is not null-terminated", (int)idx);
    return NULL;
}

/**
 * Representation of a value in a resource, supplying type
 * information.
 */
struct Res_value {
    // Number of bytes in this structure.
    uint16_t size;

    // Always set to 0.
    uint8_t res0;

    uint8_t dataType;

    // The data for this item, as interpreted according to dataType.
    uint32_t data;
};

/**
 * Reference to a string in a string pool.
 */
struct ResStringPool_ref {
    // Index into the string pool table (uint32_t-offset from the indices
    // immediately after ResStringPool_header) at which to find the location
    // of the string data in the pool.
    uint32_t index;
};

/**
 * XML tree header.  This appears at the front of an XML tree,
 * describing its content.  It is followed by a flat array of
 * ResXMLTree_node structures; the hierarchy of the XML document
 * is described by the occurrance of RES_XML_START_ELEMENT_TYPE
 * and corresponding RES_XML_END_ELEMENT_TYPE nodes in the array.
 */
struct ResXMLTree_header {
    struct ResChunk_header header;
};

/**
 * Basic XML tree node.  A single item in the XML document.  Extended info
 * about the node can be found after header.headerSize.
 */
struct ResXMLTree_node {
    struct ResChunk_header header;

    // Line number in original source file at which this element appeared.
    uint32_t lineNumber;

    // Optional XML comment that was associated with this element; -1 if none.
    struct ResStringPool_ref comment;
};

/**
 * Extended XML tree node for CDATA tags -- includes the CDATA string.
 * Appears header.headerSize bytes after a ResXMLTree_node.
 */
struct ResXMLTree_cdataExt {
    // The raw CDATA character data.
    struct ResStringPool_ref data;

    // The typed value of the character data if this is a CDATA node.
    struct Res_value typedData;
};

/**
 * Extended XML tree node for namespace start/end nodes.
 * Appears header.headerSize bytes after a ResXMLTree_node.
 */
struct ResXMLTree_namespaceExt {
    // The prefix of the namespace.
    struct ResStringPool_ref prefix;

    // The URI of the namespace.
    struct ResStringPool_ref uri;
};

/**
 * Extended XML tree node for element start/end nodes.
 * Appears header.headerSize bytes after a ResXMLTree_node.
 */
struct ResXMLTree_endElementExt {
    // String of the full namespace of this element.
    struct ResStringPool_ref ns;

    // String name of this node if it is an ELEMENT; the raw
    // character data if this is a CDATA node.
    struct ResStringPool_ref name;
};

/**
 * Extended XML tree node for start tags -- includes attribute
 * information.
 * Appears header.headerSize bytes after a ResXMLTree_node.
 */
struct ResXMLTree_attrExt {
    // String of the full namespace of this element.
    struct ResStringPool_ref ns;

    // String name of this node if it is an ELEMENT; the raw
    // character data if this is a CDATA node.
    struct ResStringPool_ref name;

    // Byte offset from the start of this structure where the attributes start.
    uint16_t attributeStart;

    // Size of the ResXMLTree_attribute structures that follow.
    uint16_t attributeSize;

    // Number of attributes associated with an ELEMENT.  These are
    // available as an array of ResXMLTree_attribute structures
    // immediately following this node.
    uint16_t attributeCount;

    // Index (1-based) of the "id" attribute. 0 if none.
    uint16_t idIndex;

    // Index (1-based) of the "class" attribute. 0 if none.
    uint16_t classIndex;

    // Index (1-based) of the "style" attribute. 0 if none.
    uint16_t styleIndex;
};

struct ResXMLTree_attribute {
    // Namespace of this attribute.
    struct ResStringPool_ref ns;

    // Name of this attribute.
    struct ResStringPool_ref name;

    // The original raw string value of this attribute.
    struct ResStringPool_ref rawValue;

    // Processesd typed value of this attribute.
    struct Res_value typedValue;
};

class ResXmlTree {
  public:
    enum event_code_t {
        BAD_DOCUMENT = -1,
        START_DOCUMENT = 0,
        END_DOCUMENT = 1,

        START_NAMESPACE = RES_XML_START_NAMESPACE_TYPE,
        END_NAMESPACE = RES_XML_END_NAMESPACE_TYPE,
        START_TAG = RES_XML_START_ELEMENT_TYPE,
        END_TAG = RES_XML_END_ELEMENT_TYPE,
        TEXT = RES_XML_CDATA_TYPE
    };

    status_t SetTo(const void* data, size_t size);
    status_t ValidateNode(const ResXMLTree_node* node) const;
    event_code_t Next();

    std::string GetElementName() const;
    size_t GetAttributeCount() const;
    std::string GetAttributeName(size_t idx) const;
    std::string GetAttributeStringValue(size_t idx) const;

  private:
    const ResXMLTree_node* mCurNode;
    const void* mCurExt;
    status_t mError;
    const ResXMLTree_header* mHeader;
    size_t mSize;
    const uint8_t* mDataEnd;
    ResStringPool mStrings;
    const ResXMLTree_node* mRootNode;
    event_code_t mEventCode;
};

status_t ResXmlTree::SetTo(const void* data, size_t size) {
    mEventCode = START_DOCUMENT;
    if (!data || !size) {
        return (mError = BAD_TYPE);
    }

    mHeader = (const ResXMLTree_header*)data;
    mSize = dtohl(mHeader->header.size);
    if (dtohs(mHeader->header.headerSize) > mSize || mSize > size) {
        printf("Bad XML block: header size %d or total size %d is larger than data size %d\n",
               (int)dtohs(mHeader->header.headerSize), (int)dtohl(mHeader->header.size), (int)size);
        mError = BAD_TYPE;
        return mError;
    }

    mDataEnd = ((const uint8_t*)mHeader) + mSize;
    mRootNode = NULL;

    // First look for a couple interesting chunks: the string block
    // and first XML node.
    const ResChunk_header* chunk =
            (const ResChunk_header*)(((const uint8_t*)mHeader) + dtohs(mHeader->header.headerSize));
    const ResChunk_header* lastChunk = chunk;
    while (((const uint8_t*)chunk) < (mDataEnd - sizeof(ResChunk_header)) &&
           ((const uint8_t*)chunk) < (mDataEnd - dtohl(chunk->size))) {
        status_t err = validate_chunk(chunk, sizeof(ResChunk_header), mDataEnd, "XML");
        if (err != NO_ERROR) {
            mError = err;
            goto done;
        }
        const uint16_t type = dtohs(chunk->type);
        const size_t size = dtohl(chunk->size);

        if (type == RES_STRING_POOL_TYPE) {
            mStrings.SetTo(chunk, size);
        } else if (type >= RES_XML_FIRST_CHUNK_TYPE && type <= RES_XML_LAST_CHUNK_TYPE) {
            if (ValidateNode((const ResXMLTree_node*)chunk) != NO_ERROR) {
                mError = BAD_TYPE;
                goto done;
            }
            mCurNode = (const ResXMLTree_node*)lastChunk;
            if (Next() == BAD_DOCUMENT) {
                mError = BAD_TYPE;
                goto done;
            }
            mRootNode = mCurNode;
            break;
        }
        lastChunk = chunk;
        chunk = (const ResChunk_header*)(((const uint8_t*)chunk) + size);
    }

    if (mRootNode == NULL) {
        printf("Bad XML block: no root element node found\n");
        mError = BAD_TYPE;
        goto done;
    }

    mError = mStrings.GetError();
done:
    return mError;
}

status_t ResXmlTree::ValidateNode(const ResXMLTree_node* node) const {
    const uint16_t eventCode = dtohs(node->header.type);

    status_t err =
            validate_chunk(&node->header, sizeof(ResXMLTree_node), mDataEnd, "ResXMLTree_node");

    if (err >= NO_ERROR) {
        // Only perform additional validation on START nodes
        if (eventCode != RES_XML_START_ELEMENT_TYPE) {
            return NO_ERROR;
        }

        const uint16_t headerSize = dtohs(node->header.headerSize);
        const uint32_t size = dtohl(node->header.size);
        const ResXMLTree_attrExt* attrExt =
                (const ResXMLTree_attrExt*)(((const uint8_t*)node) + headerSize);
        // check for sensical values pulled out of the stream so far...
        if ((size >= headerSize + sizeof(ResXMLTree_attrExt)) && ((void*)attrExt > (void*)node)) {
            const size_t attrSize =
                    ((size_t)dtohs(attrExt->attributeSize)) * dtohs(attrExt->attributeCount);
            if ((dtohs(attrExt->attributeStart) + attrSize) <= (size - headerSize)) {
                return NO_ERROR;
            }
            printf("Bad XML block: node attributes use 0x%x bytes, only have 0x%x bytes\n",
                   (unsigned int)(dtohs(attrExt->attributeStart) + attrSize),
                   (unsigned int)(size - headerSize));
        } else {
            printf("Bad XML start block: node header size 0x%x, size 0x%x\n",
                   (unsigned int)headerSize, (unsigned int)size);
        }
        return BAD_TYPE;
    }

    return err;
}

ResXmlTree::event_code_t ResXmlTree::Next() {
    if (mEventCode < 0) {
        return mEventCode;
    }

    while (true) {
        const auto Next =
                (const ResXMLTree_node*)(((const uint8_t*)mCurNode) + dtohl(mCurNode->header.size));

        if (((const uint8_t*)Next) >= mDataEnd) {
            mCurNode = NULL;
            return (mEventCode = END_DOCUMENT);
        }

        if (ValidateNode(Next) != NO_ERROR) {
            mCurNode = NULL;
            return (mEventCode = BAD_DOCUMENT);
        }

        mCurNode = Next;
        const uint16_t headerSize = dtohs(Next->header.headerSize);
        const uint32_t totalSize = dtohl(Next->header.size);
        mCurExt = ((const uint8_t*)Next) + headerSize;
        size_t miNextSize = 0;
        auto eventCode = (event_code_t)dtohs(Next->header.type);
        switch ((mEventCode = eventCode)) {
            case RES_XML_START_NAMESPACE_TYPE:
            case RES_XML_END_NAMESPACE_TYPE:
                miNextSize = sizeof(ResXMLTree_namespaceExt);
                break;
            case RES_XML_START_ELEMENT_TYPE:
                miNextSize = sizeof(ResXMLTree_attrExt);
                break;
            case RES_XML_END_ELEMENT_TYPE:
                miNextSize = sizeof(ResXMLTree_endElementExt);
                break;
            case RES_XML_CDATA_TYPE:
                miNextSize = sizeof(ResXMLTree_cdataExt);
                break;
            default:
                continue;
        }

        if ((totalSize - headerSize) < miNextSize) {
            printf("Bad XML block: header type 0x%x in node at 0x%x has size %d, need %d\n",
                   (int)dtohs(Next->header.type),
                   (int)(((const uint8_t*)Next) - ((const uint8_t*)mHeader)),
                   (int)(totalSize - headerSize), (int)miNextSize);
            return (mEventCode = BAD_DOCUMENT);
        }

        return eventCode;
    }
}

std::string ResXmlTree::GetElementName() const {
    int32_t id = -1;
    if (mEventCode == START_TAG) {
        id = dtohl(((const ResXMLTree_attrExt*)mCurExt)->name.index);
    } else if (mEventCode == END_TAG) {
        id = dtohl(((const ResXMLTree_endElementExt*)mCurExt)->name.index);
    }
    return id >= 0 ? mStrings.StringAt(id) : "";
}

size_t ResXmlTree::GetAttributeCount() const {
    if (mEventCode == START_TAG) {
        return dtohs(((const ResXMLTree_attrExt*)mCurExt)->attributeCount);
    }
    return 0;
}

std::string ResXmlTree::GetAttributeName(size_t idx) const {
    int32_t id = -1;
    if (mEventCode == START_TAG) {
        const ResXMLTree_attrExt* tag = (const ResXMLTree_attrExt*)mCurExt;
        if (idx < dtohs(tag->attributeCount)) {
            const ResXMLTree_attribute* attr =
                    (const ResXMLTree_attribute*)(((const uint8_t*)tag) +
                                                  dtohs(tag->attributeStart) +
                                                  (dtohs(tag->attributeSize) * idx));
            id = dtohl(attr->name.index);
        }
    }

    return id >= 0 ? mStrings.StringAt(id) : "";
}

std::string ResXmlTree::GetAttributeStringValue(size_t idx) const {
    int32_t id = -1;
    if (mEventCode == START_TAG) {
        const ResXMLTree_attrExt* tag = (const ResXMLTree_attrExt*)mCurExt;
        if (idx < dtohs(tag->attributeCount)) {
            const ResXMLTree_attribute* attr =
                    (const ResXMLTree_attribute*)(((const uint8_t*)tag) +
                                                  dtohs(tag->attributeStart) +
                                                  (dtohs(tag->attributeSize) * idx));
            id = dtohl(attr->rawValue.index);
        }
    }

    return id >= 0 ? mStrings.StringAt(id) : "";
}

std::string get_packagename_from_apk(const char* apk_path) {
    ZipArchiveHandle unmanaged_handle;
    int32_t result = ::OpenArchive(apk_path, &unmanaged_handle);

    if (result != 0) {
        error_exit("Failed to open APK '%s' %s", apk_path, ::ErrorCodeString(result));
    }

    ::ZipEntry entry;
    result = FindEntry(unmanaged_handle, "AndroidManifest.xml", &entry);
    if (result != 0) {
        error_exit("Unable to locate AndroidManifest.xml");
    }

    uint32_t uncompressed_length = entry.uncompressed_length;
    std::unique_ptr<uint8_t[]> data = std::unique_ptr<uint8_t[]>(new uint8_t[uncompressed_length]);
    result = ExtractToMemory(unmanaged_handle, &entry, data.get(),
                             static_cast<uint32_t>(uncompressed_length));
    if (result != 0) {
        error_exit("Unable to open AndroidManifest.xml inside %s", apk_path);
    }
    CloseArchive(unmanaged_handle);

    ResXmlTree tree;
    status_t status = tree.SetTo(data.get(), uncompressed_length);
    if (status != OK) {
        error_exit("Unable to parse AndroidManifest.xml inside %s", apk_path);
    }

    ResXmlTree::event_code_t code;
    while ((code = tree.Next()) != ResXmlTree::BAD_DOCUMENT && code != ResXmlTree::END_DOCUMENT) {
        switch (code) {
            case ResXmlTree::START_TAG: {
                const std::string element_name = tree.GetElementName();
                if (element_name == "manifest") {
                    for (size_t i = 0; i < tree.GetAttributeCount(); i++) {
                        const std::string attribute_name = tree.GetAttributeName(i);
                        if (attribute_name == "package") {
                            return tree.GetAttributeStringValue(i);
                        }
                    }
                }
                break;
            }
            default:
                break;
        }
    }

    error_exit("Unable to find package name within AndroidManifest.xml inside %s", apk_path);
    return "";
}
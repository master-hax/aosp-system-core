/*
 * Copyright (C) 2014 The Android Open Source Project
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

#ifndef LIBZIPARCHIVE_ENTRY_NAME_UTILS_INL_H_
#define LIBZIPARCHIVE_ENTRY_NAME_UTILS_INL_H_

#include <stddef.h>
#include <stdint.h>

// Default implementation of IsValidEntryName to validate entry_name byte by byte.
inline bool IsValidEntryNameByteByByte(const uint8_t* entry_name, const size_t length) {
  for (size_t i = 0; i < length; ++i) {
    const uint8_t byte = entry_name[i];
    if (byte == 0) {
      return false;
    } else if ((byte & 0x80) == 0) {
      // Single byte sequence.
      continue;
    } else if ((byte & 0xc0) == 0x80 || (byte & 0xfe) == 0xfe) {
      // Invalid sequence.
      return false;
    } else {
      // 2-5 byte sequences.
      for (uint8_t first = byte << 1; first & 0x80; first <<= 1) {
        ++i;

        // Missing continuation byte..
        if (i == length) {
          return false;
        }

        // Invalid continuation byte.
        const uint8_t continuation_byte = entry_name[i];
        if ((continuation_byte & 0xc0) != 0x80) {
          return false;
        }
      }
    }
  }

  return true;
}

// This is a specialized version of IsValidEntryName when the name contains
// sequences longer than 15 bytes.
inline bool IsValidEntryNameLenGe16(const uint8_t* entry_name, size_t length) {
  uint64_t chunk8[2];
  constexpr unsigned sz16 = 2 * sizeof(uint64_t);

  // Make a 8x vector with 0x01 and 0x80 in each byte.
  constexpr uint64_t kVdup8_01 = 0x0101010101010101;
  constexpr uint64_t kVdup8_80 = 0x8080808080808080;

  // First bytes to align length to 16.
  size_t incr = (length % sz16) ? (length % sz16) : sz16;

  while (length > 0) {
    // Load 128bit.
    __builtin_memcpy(chunk8, entry_name, sz16);

    // Is there any element in vector with value >127 (multiple byte sequence)?
    // ((byte & 0x80 ) != 0).
    if (chunk8[0] & kVdup8_80 || chunk8[1] & kVdup8_80)
      // Validate the rest of this entry with the UTF-8 validator.
      return IsValidEntryNameByteByByte(entry_name, length);

    // Is there any element in vector with value = 0 (NUL)?
    // Full zero byte check for 0-255:
    // (X - 1) & (~X) & 0x80 != 0 ==> at least one byte is zero across word.
    // Since we already check across vector that all bytes <128
    // zero check for 0-127: (X - 1) & 0x80 != 0 ==> at least one byte is zero
    // across word.
    if ((chunk8[0] - kVdup8_01) & kVdup8_80 ||
        (chunk8[1] - kVdup8_01) & kVdup8_80)
      return false;

    // None of the bytes are zero OR >127
    // all of them are single byte UTF-8 sequence.
    entry_name += incr;
    length -= incr;
    incr = sz16;
  }

  // All bytes matched single byte sequence.
  return true;
}

// Copy of the >= 16 length function to optimize length=8-15 case.
inline bool IsValidEntryNameLenGe8(const uint8_t* entry_name, size_t length) {
  uint64_t chunk8;
  constexpr unsigned sz8 = sizeof(chunk8);

  // Make a 8x vector with 0x01 and 0x80 in each byte.
  constexpr uint64_t kVdup8_01 = 0x0101010101010101;
  constexpr uint64_t kVdup8_80 = 0x8080808080808080;

  // First bytes to align length to 8.
  size_t incr = (length % sz8) ? (length % sz8) : sz8;

  while (length > 0) {
    // Load 64bit.
    __builtin_memcpy(&chunk8, entry_name, sz8);

    // Is there any element in vector with value >127 (multiple byte sequence)?
    // ((byte & 0x80 ) != 0).
    if (chunk8 & kVdup8_80)
      // Validate the rest of this entry with the UTF-8 validator.
      return IsValidEntryNameByteByByte(entry_name, length);

    // Is there any element in vector with value = 0 (NUL)?
    // Full zero byte check for 0-255:
    // (X - 1) & (~X) & 0x80 != 0 ==> at least one byte is zero across word.
    // Since we already check across vector that all bytes <128
    // zero check for 0-127: (X - 1) & 0x80 != 0 ==> at least one byte is zero
    // across word.
    if ((chunk8 - kVdup8_01) & kVdup8_80)
      return false;

    // None of the bytes are zero OR >127
    // all of them single byte UTF-8 sequence.
    entry_name += incr;
    length -= incr;
    incr = sz8;
  }

  // All bytes matched single byte sequence.
  return true;
}

// Check if |length| bytes at |entry_name| constitute a valid entry name.
// Entry names must be valid UTF-8 and must not contain '0'.
inline bool IsValidEntryName(const uint8_t* entry_name, const size_t length) {
  if (length >= 16)
    return IsValidEntryNameLenGe16(entry_name, length);

  if (length >= 8)
    return IsValidEntryNameLenGe8(entry_name, length);

  return IsValidEntryNameByteByByte(entry_name, length);
}

#endif  // LIBZIPARCHIVE_ENTRY_NAME_UTILS_INL_H_

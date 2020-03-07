/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "zip_cd_entry_map.h"

#include <log/log.h>

#include "zip_error_code.h"

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

static uint32_t ComputeHash(std::string_view name) {
  return static_cast<uint32_t>(std::hash<std::string_view>{}(name));
}

CdEntryMapZip32::CdEntryMapZip32(uint16_t num_entries) {
  hash_table_size_ = RoundUpPower2(1 + (num_entries * 4) / 3);
  hash_table_ =
      reinterpret_cast<ZipStringOffset*>(calloc(hash_table_size_, sizeof(ZipStringOffset)));
}

std::unique_ptr<CdEntryMapInterface> CdEntryMapZip32::Create(uint16_t num_entries) {
  auto entry_map = new CdEntryMapZip32(num_entries);
  if (entry_map->hash_table_ == nullptr) {
    ALOGW("Zip: unable to allocate the %u-entry hash_table, entry size: %zu",
          entry_map->hash_table_size_, sizeof(ZipStringOffset));
    return nullptr;
  }
  return std::unique_ptr<CdEntryMapInterface>(entry_map);
}

CdEntryMapZip32::~CdEntryMapZip32() {
  if (hash_table_) {
    free(hash_table_);
  }
}

// Convert a ZipEntry to a hash table index, verifying that it's in a valid range.
std::pair<int32_t, uint64_t> CdEntryMapZip32::GetCdEntryOffset(std::string_view name,
                                                               const uint8_t* start) const {
  const uint32_t hash = ComputeHash(name);

  // NOTE: (hash_table_size - 1) is guaranteed to be non-negative.
  uint32_t ent = hash & (hash_table_size_ - 1);
  while (hash_table_[ent].name_offset != 0) {
    if (hash_table_[ent].ToStringView(start) == name) {
      return {0, hash_table_[ent].name_offset};
    }
    ent = (ent + 1) & (hash_table_size_ - 1);
  }

  ALOGV("Zip: Unable to find entry %.*s", static_cast<int>(name.size()), name.data());
  return {kEntryNotFound, 0};
}

int32_t CdEntryMapZip32::AddToMap(std::string_view name, const uint8_t* start) {
  const uint64_t hash = ComputeHash(name);
  uint32_t ent = hash & (hash_table_size_ - 1);

  /*
   * We over-allocated the table, so we're guaranteed to find an empty slot.
   * Further, we guarantee that the hashtable size is not 0.
   */
  while (hash_table_[ent].name_offset != 0) {
    if (hash_table_[ent].ToStringView(start) == name) {
      // We've found a duplicate entry. We don't accept duplicates.
      ALOGW("Zip: Found duplicate entry %.*s", static_cast<int>(name.size()), name.data());
      return kDuplicateEntry;
    }
    ent = (ent + 1) & (hash_table_size_ - 1);
  }

  // `name` has already been validated before entry.
  const char* start_char = reinterpret_cast<const char*>(start);
  hash_table_[ent].name_offset = static_cast<uint32_t>(name.data() - start_char);
  hash_table_[ent].name_length = static_cast<uint16_t>(name.size());
  return 0;
}

void CdEntryMapZip32::ResetIteration() {
  current_position_ = 0;
}

std::pair<std::string_view, uint64_t> CdEntryMapZip32::Next(const uint8_t* cd_start) {
  if (current_position_ >= hash_table_size_) {
    return {};
  }

  const auto& entry = hash_table_[current_position_];
  current_position_ += 1;
  if (entry.name_offset != 0) {
    return {entry.ToStringView(cd_start), entry.name_offset};
  }
  // Advance to the next hash table entry if the current one is uninitialized.
  return Next(cd_start);
}

std::unique_ptr<CdEntryMapInterface> CdEntryMapZip64::Create() {
  return std::unique_ptr<CdEntryMapZip64>(new CdEntryMapZip64());
}

int32_t CdEntryMapZip64::AddToMap(std::string_view name, const uint8_t* start) {
  if (entry_table_.find(name) != entry_table_.end()) {
    ALOGW("Zip: Found duplicate entry %.*s", static_cast<int>(name.size()), name.data());
    return kDuplicateEntry;
  }

  const auto [it, success] =
      entry_table_.insert({name, name.data() - reinterpret_cast<const char*>(start)});
  if (!success) {
    ALOGW("Zip: Error adding entry to hash table");
    return kAllocationFailed;
  }
  return 0;
}

std::pair<int32_t, uint64_t> CdEntryMapZip64::GetCdEntryOffset(std::string_view name,
                                                               const uint8_t* /*cd_start*/) const {
  const auto it = entry_table_.find(name);
  if (it == entry_table_.end()) {
    ALOGV("Zip: Could not find entry %.*s", static_cast<int>(name.size()), name.data());
    return {kEntryNotFound, 0};
  }

  return {0, it->second};
}

void CdEntryMapZip64::ResetIteration() {
  iterator_ = entry_table_.begin();
}

std::pair<std::string_view, uint64_t> CdEntryMapZip64::Next(const uint8_t* /*cd_start*/) {
  if (iterator_ == entry_table_.end()) {
    return {};
  }

  auto result = *iterator_;
  iterator_++;
  return result;
}

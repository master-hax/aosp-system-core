/*
 *  Copyright 2018 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef _LIBDM_DMTABLE_H_
#define _LIBDM_DMTABLE_H_

#include <string>
#include <vector>

#include "dm_target.h"

namespace android {
namespace dm {

class DmTable {
  public:
    DmTable() : size_(0) {};
    // Constructs a table using the list of targets already prepared.
    // FIXME: Not sure if we need this yet.
    // DmTable(const std::vector<DmTarget>& targets);

    // Adds a target to the device mapper table for a range specified in the target object.
    // The function will return 'true' if the target was successfully added and doesn't overlap with
    // any of the existing targets in the table. Gaps are allowed. The final check, including
    // overlaps and gaps are done before loading the table. Returns 'false' on failure.
    bool AddTarget(const DmTarget& target);

    // Removes a target from the table for the range specified in the target object. Returns 'false'
    // iof the target name doesn't match with the one in the table. Returns 'true' if target is
    // successfully removed.
    bool RemoveTarget(const DmTarget& target);

    // Checks the table to make sure it is valid. i.e. Checks for range overlaps, range gaps
    // and returns 'true' if the table is ready to be loaded into kernel. Returns 'false' if the
    // table is malformed.
    bool IsValid(void) const;

    // Returns the total size represented by the table in terms of number of 512-byte sectors.
    // NOTE: This function will overlook if there are any gaps in the targets added in the table.
    uint64_t getSize(void) const;

    // Returns the string represntation of the table that is ready to be passed into the kernel
    // as part of the DM_TABLE_LOAD ioctl.
    std::string Serialize(void) const;

    ~DmTable() = default;

  private:
    // list of targets defined in this table sorted by
    // their start and end sectors.
    // Note: Overlapping targets MUST never be added in this list.
    std::vector<DmTarget> targets_;

    // Total size in terms of # of sectores, as calculated by looking at the last and the first
    // target in 'target_'.
    uint64_t size_;
};

}  // namespace dm
}  // namespace android

#endif /* _LIBDM_DMTABLE_H_ */

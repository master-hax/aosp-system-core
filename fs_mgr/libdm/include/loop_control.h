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

#ifndef _LIBDM_LOOP_CONTROL_H_
#define _LIBDM_LOOP_CONTROL_H_

#include <errno.h>
#include <fcntl.h>
#include <linux/loop.h>
#include <unistd.h>

#include <android-base/logging.h>

class LoopControl final {
  public:
    LoopControl() : control_fd_(-1) {
        control_fd_ = TEMP_FAILURE_RETRY(open(kLoopControlDevice, O_RDWR | O_CLOEXEC));
        if (control_fd_ < 0) {
            PLOG(ERROR) << "Failed to open loop-control";
        }
    };

    // Attaches the file specified by 'path' to the loop back device specified
    // by 'loopdev'
    bool attach(const std::string& path, std::string* loopdev) const;

    // detach loopback device given by 'loopdev' form the attached backing file.
    bool detach(const std::string& loopdev) const;

    // Takes care of closing loop-control device
    ~LoopControl();

  private:
    bool FindFreeLoopDevice(std::string* loopdev) const;

    static constexpr const char* kLoopControlDevice = "/dev/loop-control";

    int control_fd_;
};

#endif /* _LIBDM_LOOP_CONTROL_H_ */

#!/usr/bin/python
#
# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This script extracts two bootchart.tgz files and compares the time stamps
# in proc_ps.log for selected processes. The proc_ps.log file consists of
# repetitive blocks of the following format:
#
# time_stamp1 (unit is Jiffy 10 ms)
# dumps of /proc/<pid>/stat
#
# time_stamp2
# dumps of /proc/<pid>/stat
#
# The time stamps are 200ms (ie 20 Jiffies) apart, and the creation time of
# selected processes are listed. The termination time of the boot animation
# process is also listed as a coarse indication about when the boot process is
# complete as perceived by the user.
#

import sys
import tarfile

def analyzeProcessLists(process_list1, process_list2):
    # List interesting processes here
    processes_of_interest = ['/init',
                             '/system/bin/surfaceflinger',
                             '/system/bin/bootanimation',
                             'zygote64',
                             'zygote',
                             'system_server',
                            ]

    print("process: baseline experiment (delta)")
    print("unit is ms")
    print("------------------------------------")
    for p in processes_of_interest:
        print("%s: %d %d (%+d)" %
              (p, process_list1[p]['startTime'], process_list2[p]['startTime'],
               process_list2[p]['startTime'] - process_list1[p]['startTime']))

    # Print the last tick for the bootanimation process
    print("bootanimation ends at: %d %d (%+d)" %
          (process_list1['/system/bin/bootanimation']['lastTick'],
           process_list2['/system/bin/bootanimation']['lastTick'],
           process_list2['/system/bin/bootanimation']['lastTick'] -
           process_list1['/system/bin/bootanimation']['lastTick']))

def praseProcFile(pathname, process_list):
    # Uncompress bootchart.tgz
    tf = tarfile.open(pathname+'/bootchart.tgz', 'r:*')

    # Read proc_ps.log
    f = tf.extractfile('proc_ps.log')

    # Break proc_ps into chunks based on timestamps
    blocks = f.read().split('\n\n')
    for b in blocks:
        lines = b.split('\n')
        if not lines[0]:
            break

        # Original unit is Jiffy (10 ms)
        timestamp = int(lines[0]) * 10;

        # Populate the process_list table
        for line in lines[1:]:
            segs = line.split(' ')
            """
             0: pid
             1: process name
            17: priority
            18: nice
            21: creation time
            """
            procName = segs[1].strip('()')
            if procName in process_list.keys():
                process = process_list[procName]
            else:
                process = {'startTime':int(segs[21])*10}
                process_list[procName] = process
            process['lastTick'] = timestamp
    f.close()

def main():
    if (len(sys.argv) != 3):
        print("Usage: %s base_bootchart_dir exp_bootchart_dir" % sys.argv[0])
        sys.exit(1)

    process_list1 = {}
    process_list2 = {}
    praseProcFile(sys.argv[1], process_list1)
    praseProcFile(sys.argv[2], process_list2)
    analyzeProcessLists(process_list1, process_list2)

if __name__ == "__main__":
    sys.exit(main())

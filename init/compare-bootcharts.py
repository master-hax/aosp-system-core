#!/usr/bin/env python
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

"""Compare two bootcharts and list start/end timestamps on key processes.

This script extracts two bootchart.tgz files and compares the timestamps
in proc_ps.log for selected processes. The proc_ps.log file consists of
repetitive blocks of the following format:

timestamp1 (unit is Jiffy 10 ms)
dumps of /proc/<pid>/stat

timestamp2
dumps of /proc/<pid>/stat

The timestamps are 200ms (ie 20 Jiffies) apart, and the creation time of
selected processes are listed. The termination time of the boot animation
process is also listed as a coarse indication about when the boot process is
complete as perceived by the user.
"""

import sys
import tarfile

def analyze_process_maps(process_map1, process_map2):
    # List interesting processes here
    processes_of_interest = [
        '/init',
        '/system/bin/surfaceflinger',
        '/system/bin/bootanimation',
        'zygote64',
        'zygote',
        'system_server'
    ]

    print "process: baseline experiment (delta)"
    print "unit is ms"
    print "------------------------------------"
    for p in processes_of_interest:
        print "%s: %d %d (%+d)" % (
            p, process_map1[p]['startTime'], process_map2[p]['startTime'],
            process_map2[p]['startTime'] - process_map1[p]['startTime'])

    # Print the last tick for the bootanimation process
    print "bootanimation ends at: %d %d (%+d)" % (
        process_map1['/system/bin/bootanimation']['lastTick'],
        process_map2['/system/bin/bootanimation']['lastTick'],
        process_map2['/system/bin/bootanimation']['lastTick'] -
            process_map1['/system/bin/bootanimation']['lastTick'])

def parse_proc_file(pathname, process_map):
    # Uncompress bootchart.tgz
    with tarfile.open(pathname + '/bootchart.tgz', 'r:*') as tf:
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

            # Populate the process_map table
            for line in lines[1:]:
                segs = line.split(' ')

                #  0: pid
                #  1: process name
                # 17: priority
                # 18: nice
                # 21: creation time

                procName = segs[1].strip('()')
                if procName in process_map:
                    process = process_map[procName]
                else:
                    process = {'startTime': int(segs[21]) * 10}
                    process_map[procName] = process
                process['lastTick'] = timestamp

    f.close()

def main():
    if len(sys.argv) != 3:
        print "Usage: %s base_bootchart_dir exp_bootchart_dir" % sys.argv[0]
        sys.exit(1)

    process_map1 = {}
    process_map2 = {}
    parse_proc_file(sys.argv[1], process_map1)
    parse_proc_file(sys.argv[2], process_map2)
    analyze_process_maps(process_map1, process_map2)

if __name__ == "__main__":
    main()

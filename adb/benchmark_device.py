#!/usr/bin/env python3
#
# Copyright (C) 2018 The Android Open Source Project
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

import os
import statistics
import time

import adb

def run_script(device, script):
    stripped = [line.strip() for line in script.splitlines() if len(line.strip())]
    return device.shell([";".join(stripped)])

def lock_min(device):
    run_script(device, """
        echo userspace > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
        for x in /sys/devices/system/cpu/cpu?/cpufreq
            do cat $x/scaling_min_freq > $x/scaling_setspeed
        done
    """)

def lock_max(device):
    run_script(device, """
        echo userspace > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
        for x in /sys/devices/system/cpu/cpu?/cpufreq
            do cat $x/scaling_max_freq > $x/scaling_setspeed
        done
    """)

def unlock(device):
    run_script(device, """
        echo ondemand > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
        echo sched > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
        echo schedutil > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
    """)

def harmonic_mean(xs):
    return 1.0 / statistics.mean([1.0 / x for x in xs])

def analyze(name, speeds):
    median = statistics.median(speeds)
    mean = harmonic_mean(speeds)
    stddev = statistics.stdev(speeds)
    msg = "%s: %d runs: median %.2f MiB/s, mean %.2f MiB/s, stddev: %.2f MiB/s"
    print(msg % (name, len(speeds), median, mean, stddev))

def benchmark_push(device=None, file_size_mb=100):
    if device == None:
        device = adb.get_device()

    lock_max(device)

    remote_path = "/dev/null"
    local_path = "/tmp/adb_benchmark_temp"

    with open(local_path, "wb") as f:
        f.truncate(file_size_mb * 1024 * 1024)

    speeds = list()
    for _ in range(0, 5):
        begin = time.time()
        device.push(local=local_path, remote=remote_path)
        end = time.time()
        speeds.append(file_size_mb / float(end - begin))

    analyze("push %dMiB" % file_size_mb, speeds)

def benchmark_pull(device=None, file_size_mb=100):
    if device == None:
        device = adb.get_device()

    lock_max(device)

    remote_path = "/data/local/tmp/adb_benchmark_temp"
    local_path = "/tmp/adb_benchmark_temp"

    device.shell(["dd", "if=/dev/zero", "of=" + remote_path, "bs=1m",
                  "count=" + str(file_size_mb)])
    speeds = list()
    for _ in range(0, 5):
        begin = time.time()
        device.pull(remote=remote_path, local=local_path)
        end = time.time()
        speeds.append(file_size_mb / float(end - begin))

    analyze("pull %dMiB" % file_size_mb, speeds)

def main():
    benchmark_pull()

if __name__ == "__main__":
    main()

#!/usr/bin/env python

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

"""Record the event logs during boot and output them to a file.

This script repeats the record of each event log during Android boot specified
times. By default, interval between measurements is adjusted in such a way that
CPUs are cooled down sufficiently to avoid boot time slowdown caused by CPU
thermal throttling. The result is output in a tab-separated value format.

Examples:

Repeat measurements 10 times. Interval between iterations is adjusted based on
CPU temperature of the device.

$ ./perfboot.py --iterations=10

Repeat measurements 20 times. 60 seconds interval is taken between each
iteration.

$ ./perfboot.py --iterations=20 --interval=60

Repeat measurements 20 times, show verbose output, output the result to
data.tsv, and read event tags from eventtags.txt.

$ ./perfboot.py --iterations=30 -v --output=data.tsv --tags=eventtags.txt
"""

import argparse
import atexit
import cStringIO
import logging
import math
import os
import re
import subprocess
import threading
import time

# The default event tags to record.
_DEFAULT_EVENT_TAGS = [
    'boot_progress_start',
    'boot_progress_preload_start',
    'boot_progress_preload_end',
    'boot_progress_system_run',
    'boot_progress_pms_start',
    'boot_progress_pms_system_scan_start',
    'boot_progress_pms_data_scan_start',
    'boot_progress_pms_scan_end',
    'boot_progress_pms_ready',
    'boot_progress_ams_ready',
    'boot_progress_enable_screen',
]
# The time out value to stop iteration
_TIMEOUT = 120
# The device serial used by adb commands. Initialized by --serial option
_ANDROID_SERIAL = None
# The number of times to retry adb command
_RUN_ADB_RETRIES = 3


class IntervalAdjuster(object):
    """A helper class to take suffficient interval between iterations. """

    # CPU temperature values per product used to decide interval
    _CPU_COOL_DOWN_THRESHOLDS = {
        'flo': 40,
        'flounder': 40000,
        'razor': 40,
        'volantis': 40000,
    }
    # The interval between CPU temperature checks
    _CPU_COOL_DOWN_WAIT_INTERVAL = 10
    # The wait time used when the value of _CPU_COOL_DOWN_THRESHOLDS for
    # the product is not defined.
    _CPU_COOL_DOWN_WAIT_TIME_DEFAULT = 120

    def __init__(self, interval):
        self._interval = interval
        self._temp_paths = run_adb(
            ['shell', 'ls',
             '/sys/class/thermal/thermal_zone*/temp']).splitlines()
        self._product = get_property('ro.build.product')
        self._waited = False

    def wait(self):
        """Waits certain amount of time for CPUs cool-down."""
        if self._interval is None:
            IntervalAdjuster._wait_cpu_cool_down(
                self._product, self._temp_paths)
        else:
            if self._waited:
                print 'Waiting for %d seconds' % self._interval
                time.sleep(self._interval)
        self._waited = True

    @classmethod
    def _get_cpu_temp(cls, threshold, temp_paths):
        max_temp = 0
        for temp_path in temp_paths:
            temp = int(run_adb(['shell', 'cat', temp_path]).rstrip())
            max_temp = max(max_temp, temp)
            if (temp >= threshold):
                return temp
        return max_temp

    @classmethod
    def _wait_cpu_cool_down(cls, product, temp_paths):
        threshold = cls._CPU_COOL_DOWN_THRESHOLDS.get(product)
        if not threshold:
            print 'No CPU temperature threshold is set for ' + product
            print 'Just wait %d seconds' % cls._CPU_COOL_DOWN_WAIT_TIME_DEFAULT
            time.sleep(cls._CPU_COOL_DOWN_WAIT_TIME_DEFAULT)
            return
        while True:
            temp = cls._get_cpu_temp(threshold, temp_paths)
            if temp < threshold:
                logging.info('Current CPU temperature %s' % temp)
                return
            print 'Waiting until CPU temperature (%d) falls below %d' % (
                temp, threshold)
            time.sleep(cls._CPU_COOL_DOWN_WAIT_INTERVAL)


def readlines_unbuffered(proc):
    """Read lines from |proc|'s standard out without buffering."""
    while True:
        buf = []
        c = proc.stdout.read(1)
        if c == '' and proc.poll() is not None:
            break
        while c != '\n':
            if c == '' and proc.poll() is not None:
                break
            buf.append(c)
            c = proc.stdout.read(1)
        yield ''.join(buf)


def run_cmd(cmd, cwd=None):
    """Runs |cmd| in |cwd|."""
    logging.info(' '.join(cmd))
    return subprocess.check_output(cmd, cwd=cwd)


def run_adb(cmd):
    """Runs adb command with retries on error."""
    adb = ['adb']
    if _ANDROID_SERIAL:
        adb += ['-s', _ANDROID_SERIAL]
    args = adb + cmd
    for i in range(_RUN_ADB_RETRIES):
        try:
            return run_cmd(args)
        except subprocess.CalledProcessError:
            if i < _RUN_ADB_RETRIES - 1:
                time.sleep(1 << i)
                continue
            raise


def wait_for_device():
    """Waits for the device."""
    run_adb(['wait-for-device'])


def reboot_device():
    """Reboots the device."""
    run_adb(['reboot'])


def get_property(name):
    """Gets a property from the device."""
    return run_adb(['shell', 'getprop', name]).rstrip()


def disable_dropbox():
    """Removes the files created by Dropbox and avoids creating the files."""
    run_adb(['root'])
    wait_for_device()
    run_adb(['shell', 'rm', '-rf', '/system/data/dropbox'])
    original_dropgox_max_files = run_adb(
        ['shell', 'settings', 'get', 'global', 'dropbox_max_files']).rstrip()
    run_adb(['shell', 'settings', 'put', 'global', 'dropbox_max_files', '0'])
    return original_dropgox_max_files


def restore_dropbox(original_dropgox_max_files):
    """Restores the dropbox_max_files setting."""
    run_adb(['root'])
    wait_for_device()
    if original_dropgox_max_files == 'null':
        run_adb(['shell', 'settings', 'delete', 'global',
                 'dropbox_max_files'])
    else:
        run_adb(['shell', 'settings', 'put', 'global',
                 'dropbox_max_files', original_dropgox_max_files])


def init_perf(output, record_list, tags):
    wait_for_device()
    build_type = get_property('ro.build.type')
    original_dropgox_max_files = None
    if build_type != 'user':
        # Workaround for Dropbox issue (http://b/20890386).
        original_dropgox_max_files = disable_dropbox()

    def cleanup():
        try:
            if record_list:
                print_summary(record_list, tags[-1])
                output_results(output, record_list, tags)
            if original_dropgox_max_files is not None:
                restore_dropbox(original_dropgox_max_files)
        except subprocess.CalledProcessError:
            pass
    atexit.register(cleanup)


def read_event_tags(tags_file):
    """Reads event tags from |tags_file|."""
    if not tags_file:
        return _DEFAULT_EVENT_TAGS
    tags = []
    with open(tags_file) as f:
        for line in f:
            if '#' in line:
                line = line[:line.find('#')]
            line = line.strip()
            if line:
                tags.append(line)
    return tags


def make_event_tags_re(tags):
    """Makes a regular expression object that matches event logs of |tags|."""
    return re.compile(r'(?P<pid>[0-9]+) +[0-9]+ I (?P<tag>%s): (?P<time>\d+)' %
                      '|'.join(tags))


def get_values(record, tag):
    """Gets values that matches |tag| from |record|."""
    keys = [key for key in record.keys() if key[0] == tag]
    return [record[k] for k in sorted(keys)]


def get_last_value(record, tag):
    """Gets the last value that matches |tag| from |record|."""
    values = get_values(record, tag)
    if not values:
        return 0
    return values[-1]


def output_results(filename, record_list, tags):
    """Outputs |record_list| into |filename| in a TSV format."""
    # First, count the number of the values of each tag.
    # This is for dealing with events that occur multiple times.
    # For instance, boot_progress_preload_start and boot_progress_preload_end
    # are recorded twice on 64-bit system. One is for 64-bit zygote process
    # and the other is for 32-bit zygote process.
    values_counter = {}
    for record in record_list:
        for tag in tags:
            # Some record might lack values for some tags due to unanticipated
            # problems (e.g. timeout), so take the maximum count among all the
            # record.
            values_counter[tag] = max(values_counter.get(tag, 1),
                                      len(get_values(record, tag)))

    # Then creates labels for the data. If there are multiple values for one
    # tag, labels for these values are numbered except the first one as
    # follows:
    #
    # event_tag event_tag2 event_tag3
    #
    # The corresponding values are sorted in an ascending order of PID.
    labels = []
    for tag in tags:
        for i in range(1, values_counter[tag] + 1):
            labels.append('%s%s' % (tag, '' if i == 1 else str(i)))

    # Finally write the data into the file.
    with open(filename, 'w') as f:
        f.write('\t'.join(labels) + '\n')
        for record in record_list:
            line = cStringIO.StringIO()
            invalid_line = False
            for i, tag in enumerate(tags):
                if i != 0:
                    line.write('\t')
                values = get_values(record, tag)
                if len(values) < values_counter[tag]:
                    invalid_line = True
                    # Fill invalid record with 0
                    values += [0] * (values_counter[tag] - len(values))
                line.write('\t'.join(str(t) for t in values))
            if invalid_line:
                logging.error('Invalid record found: ' + line.getvalue())
            line.write('\n')
            f.write(line.getvalue())
    print 'Wrote: ' + filename


def median(data):
    """Calculates the median value from |data|."""
    data = sorted(data)
    n = len(data)
    if n % 2 == 1:
        return data[n / 2]
    else:
        n2 = n / 2
        return (data[n2 - 1] + data[n2]) / 2.0


def mean(data):
    """Calculates the mean value from |data|."""
    return 1.0 * sum(data) / len(data)


def stddev(data):
    """Calculates the standard deviation value from |value|."""
    m = mean(data)
    return math.sqrt(sum((x - m) ** 2 for x in data) / len(data))


def print_summary(record_list, end_tag):
    """Prints the summary of |record_list|"""
    end_times = [get_last_value(record, end_tag) for record in record_list]
    # Filter out invalid data
    end_times = [t for t in end_times if t != 0]
    print 'mean: ', mean(end_times)
    print 'median:', median(end_times)
    print 'standard deviation:', stddev(end_times)


def start_watchdog_timer(timedout):
    """Starts a watch dog timer and returns it."""
    def notify_timeout():
        timedout.append(True)
    t = threading.Timer(_TIMEOUT, notify_timeout)
    t.daemon = True
    t.start()
    return t


def do_iteration(interval_adjuster, event_tags_re, end_tag):
    """Measures the boot time once."""
    wait_for_device()
    interval_adjuster.wait()
    reboot_device()
    print 'Rebooted the device'
    record = {}
    booted = False
    timedout = []
    while not booted:
        wait_for_device()
        t = start_watchdog_timer(timedout)
        p = subprocess.Popen(
                ['adb', 'logcat', '-b', 'events', '-v', 'threadtime'],
                stdout=subprocess.PIPE)
        for line in readlines_unbuffered(p):
            if timedout:
                print '*** Timed out ***'
                return record
            m = event_tags_re.search(line)
            if not m:
                continue
            tag = m.group('tag')
            event_time = int(m.group('time'))
            pid = m.group('pid')
            record[(tag, pid)] = event_time
            print 'Event log recored: %s (%s) - %d ms' % (tag, pid, event_time)
            if tag == end_tag:
                booted = True
                t.cancel()
                break
    return record


def parse_args():
    """Parses the command line arguments."""
    parser = argparse.ArgumentParser(description='Android boot pert test.')
    parser.add_argument('--iterations', type=int, default=5,
                        help='number of times to repeat boot measurements.')
    parser.add_argument('--interval', type=int,
                        help=('duration between iterations. If this is not '
                              'set explicitly, durations are determined '
                              'adaptively based on CPUs temperature.'))
    parser.add_argument('-o', '--output', help='file name of output data')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show verbose output')
    parser.add_argument('-s', '--serial', default=os.getenv('ANDROID_SERIAL'),
                        help='adb device serial number')
    parser.add_argument('-t', '--tags', help='specify the filename from which '
                        'event tags are read. Every line contains one event '
                        'tag and the last event tag is used to detect that '
                        'the device has finished booting.')
    return parser.parse_args()


def main():
    args = parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    if args.serial:
        global _ANDROID_SERIAL
        _ANDROID_SERIAL = args.serial

    if not args.output:
        wait_for_device()
        args.output = 'perf-%s-%s.tsv' % (
            get_property('ro.build.flavor'),
            get_property('ro.build.version.incremental'))

    record_list = []
    event_tags = read_event_tags(args.tags)
    init_perf(args.output, record_list, event_tags)
    interval_adjuster = IntervalAdjuster(args.interval)
    event_tags_re = make_event_tags_re(event_tags)
    end_tag = event_tags[-1]
    for i in range(args.iterations):
        print 'Run #%d ' % i
        record = do_iteration(interval_adjuster, event_tags_re, end_tag)
        record_list.append(record)


if __name__ == '__main__':
    main()

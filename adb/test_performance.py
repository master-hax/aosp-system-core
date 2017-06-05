#!/usr/bin/env python
#
# Copyright (C) 2017 The Android Open Source Project
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
"""Simple performance test for the adb program.
"""
from __future__ import print_function

import os
import random
import shutil
import subprocess
import tempfile
import time

import adb


class AdbPerformanceTest(object):
    """Adb performance test"""
    SCRATCH_DIR = '/data/local/tmp'
    DEVICE_TEST_FILE = SCRATCH_DIR + '/adb_perf_test_file'
    DEVICE_TEST_DIR = SCRATCH_DIR + '/adb_perf_test_dir'

    def __init__(self):
        self.device = adb.get_device()
        self.results = []

    def _create_temp_file(self, size, parent_dir=None):
        """Create a random file of given size. Return path to the new file. """
        f = tempfile.NamedTemporaryFile(mode='wb', dir=parent_dir, delete=False)
        f.write(os.urandom(size))
        f.close()
        return f.name

    def _create_temp_dir_of_files(self, size_each, n):
        """Create a temp dir with random files of given size. Return path to the new dir."""
        d = tempfile.mkdtemp()
        os.chmod(d, 0o700)  # Make sure the temp directory isn't setuid, or else adb will complain.
        for i in xrange(n):
            self._create_temp_file(size_each, d)
        return d

    def _format_size(self, size_in_byte):
        """Format size in byte and return a human readable size string"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if abs(size_in_byte) < 1024.0:
                return "{:3.1f}{}".format(size_in_byte, unit)
            size_in_byte /= 1024.0

    def put_result(self, test, result):
        """Put a result entry ["test description", time used]"""
        self.results.append([test, result])

    def print_results(self):
        """Print formatted test results"""
        print("Adb performance test results:")
        print("\n".join(["{:65} {:10.2f} (s)".format(r[0], r[1]) for r in self.results]))

    def test_adb_push_pull_file(self, size):
        test_file = self._create_temp_file(size)

        t0 = time.time()
        self.device.push(local=test_file, remote=self.DEVICE_TEST_FILE)
        t1 = time.time()
        self.put_result(
            'Push 1 file of {} with "adb push"'.format(self._format_size(size)), t1 - t0)

        t0 = time.time()
        self.device.pull(remote=self.DEVICE_TEST_FILE, local=test_file)
        t1 = time.time()
        self.put_result(
            'Pull 1 file of {} with "adb pull"'.format(self._format_size(size)), t1 - t0)

        self.device.shell(['rm', '-f', self.DEVICE_TEST_FILE])
        os.remove(test_file)

    def test_shell_push_pull_file(self, size):
        test_file = self._create_temp_file(size)

        t0 = time.time()
        cmd = "cat {} | adb shell 'cat > {}'".format(test_file, self.DEVICE_TEST_FILE)
        subprocess.check_call(cmd, shell=True)
        t1 = time.time()
        self.put_result(
            "Push 1 file of {} with shell pipeline".format(self._format_size(size)), t1 - t0)

        t0 = time.time()
        cmd = "adb shell cat {} > {}".format(self.DEVICE_TEST_FILE, test_file)
        subprocess.check_call(cmd, shell=True)
        t1 = time.time()
        self.put_result(
            "Pull 1 file of {} with shell pipeline".format(self._format_size(size)), t1 - t0)

        self.device.shell(['rm', '-f', self.DEVICE_TEST_FILE])
        os.remove(test_file)

    def test_adb_push_pull_multiple_files(self, size_each, n):
        test_dir = self._create_temp_dir_of_files(size_each, n)
        self.device.shell(['rm', '-rf', self.DEVICE_TEST_DIR])
        self.device.shell(['mkdir', self.DEVICE_TEST_DIR])

        t0 = time.time()
        self.device.push(local=test_dir + "/.", remote=self.DEVICE_TEST_DIR)
        t1 = time.time()
        self.put_result(
            'Push {} files of {} with "adb push"'.format(n, self._format_size(size_each)), t1 - t0)

        t0 = time.time()
        self.device.pull(remote=self.DEVICE_TEST_DIR + "/.", local=test_dir)
        t1 = time.time()
        self.put_result(
            'Pull {} files of {} with "adb pull"'.format(n, self._format_size(size_each)), t1 - t0)

        self.device.shell(['rm', '-rf', self.DEVICE_TEST_DIR])
        shutil.rmtree(test_dir)

    def run_all_tests(self):
        MICRO_FILE_SIZE = 1024 * 1024 / 32
        SMALL_FILE_SIZE = 1024 * 1024
        LARGE_FILE_SIZE = 100 * 1024 * 1024
        MULTI_FILE_TOTAL = 100 * 1024 * 1024

        self.test_adb_push_pull_file(SMALL_FILE_SIZE)
        self.test_shell_push_pull_file(SMALL_FILE_SIZE)
        self.test_adb_push_pull_file(LARGE_FILE_SIZE)
        self.test_shell_push_pull_file(LARGE_FILE_SIZE)
        self.test_adb_push_pull_multiple_files(SMALL_FILE_SIZE, MULTI_FILE_TOTAL / SMALL_FILE_SIZE)
        self.test_adb_push_pull_multiple_files(MICRO_FILE_SIZE, MULTI_FILE_TOTAL / MICRO_FILE_SIZE)
        
        self.print_results()

def main():
    random.seed(0)
    if len(adb.get_devices()) > 0:
        pf = AdbPerformanceTest()
        pf.run_all_tests()
    else:
        print('Test suite must be run with attached devices')

if __name__ == '__main__':
    main()


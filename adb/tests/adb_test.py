#!/usr/bin/python
"""
Simple conformance test for adb.
"""
import unittest
import subprocess
import re
import tempfile
import os
import hashlib

def call(cmd_str):
    """ Run process and return output tuple (stdout, stderr, ret code) """
    process = subprocess.Popen(cmd_str.split(),
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return stdout, stderr, process.returncode

def call_combine(cmd_str):
    """ Run process and return output tuple (stdout, stderr, ret code) """
    process = subprocess.Popen(cmd_str.split(),
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    stdout, _ = process.communicate()
    return stdout, process.returncode

def call_checked(cmd_str):
    """ Run process and get stdout+stderr, raise an exception on trouble """
    return subprocess.check_output(cmd_str.split(), stderr=subprocess.STDOUT)

def call_checked_list(cmd_str):
    return call_checked(cmd_str).split('\n')

def call_checked_list_skip(cmd_str):
    out_list = call_checked_list(cmd_str)
    is_init_line = lambda x: (len(x) >= 3) and (x[0] == "*") and (x[-2] == "*")
    return [line for line in out_list if not is_init_line(line)]

def get_device_list(qualifiers=False):
    output = call_checked_list_skip("adb devices")
    dev_list = []
    for line in output[1:]:
        if line.find("device") != -1:
            dev_list.append(line.split()[0])
    return dev_list

def get_attached_device_count():
    return len(get_device_list())

def compute_md5(string):
    hsh = hashlib.md5()
    hsh.update(string)
    return hsh.hexdigest()

class AdbWrapper(object):
    """ Convenience wrapper object for the adb command """
    def __init__(self, device=None):
        self.device = device
        if self.device:
            self.adb_cmd = "adb -s {} ".format(device)
        else:
            self.adb_cmd = "adb "
    def shell(self, cmd):
        return call_checked(self.adb_cmd + "shell " + cmd)
    def shell_nocheck(self, cmd):
        return call_combine(self.adb_cmd + "shell " + cmd)
    def push(self, local, remote):
        return call_checked(self.adb_cmd + "push {} {}".format(local, remote))
    def pull(self, remote, local):
        return call_checked(self.adb_cmd + "pull {} {}".format(remote, local))
    def sync(self, directory=""):
        return call_checked(self.adb_cmd + "sync {}")

class AdbBasic(unittest.TestCase):
    def setUp(self):
        pass
    def tearDown(self):
        pass
    def test_devices(self):
        """ Get uptime for each device plugged in from /proc/uptime """
        dev_list = get_device_list()
        for device in dev_list:
            out = call_checked("adb -s {} shell cat /proc/uptime".format(device))
            self.assertTrue(len(out.split()) == 2)
            self.assertTrue(float(out.split()[0]) > 0.0)
            self.assertTrue(float(out.split()[1]) > 0.0)

    def test_devices_with_qualifiers(self):
        """ Get uptime for each device plugged in from /proc/uptime """
        dev_list = get_device_list(qualifiers=True)
        for device in dev_list:
            out = call_checked("adb -s {} shell cat /proc/uptime".format(device))
            self.assertTrue(len(out.split()) == 2)
            self.assertTrue(float(out.split()[0]) > 0.0)
            self.assertTrue(float(out.split()[1]) > 0.0)

    def test_help(self):
        """ Make sure we get _something_ out of help """
        out = call_checked("adb help")
        self.assertTrue(len(out) > 0)

    def test_version(self):
        """ Get a version number out of the output of adb """
        out = call_checked("adb version").split()
        version_num = False
        for item in out:
            if re.match(r"[\d+\.]*\d", item):
                version_num = True
        self.assertTrue(version_num)

SCRATCH_DIR = "/data/local"
DEVICE_TEMP_FILE = SCRATCH_DIR + "/tmp"

class AdbFile(unittest.TestCase):
    def test_push(self):
        """ Push a file to all attached devices """
        dev_list = get_device_list()
        for device in dev_list:
            self.push_with_device(device)

    def push_with_device(self, device):
        """ Push a randomly generated file to specified device """
        kbytes = 512
        adb = AdbWrapper(device)
        with tempfile.NamedTemporaryFile(mode="w") as tmp:
            rand_str = os.urandom(1024 * kbytes)
            tmp.write(rand_str)
            tmp.flush()

            host_md5 = compute_md5(rand_str)
            adb.shell_nocheck("rm -r {}".format(DEVICE_TEMP_FILE))
            try:
                adb.push(local=tmp.name, remote=DEVICE_TEMP_FILE)
                dev_md5, _ = adb.shell("md5 {}".format(DEVICE_TEMP_FILE)).split()
                self.assertEqual(host_md5, dev_md5)
            finally:
                adb.shell_nocheck("rm {}".format(DEVICE_TEMP_FILE))

    def test_pull(self):
        """ Pull a file from all attached devices """
        dev_list = get_device_list()
        for device in dev_list:
            self.pull_with_device(device)

    def pull_with_device(self, device):
        """ Pull a randomly generated file from specified device """
        kbytes = 512
        adb = AdbWrapper(device)
        adb.shell_nocheck("rm -r {}".format(DEVICE_TEMP_FILE))
        try:
            adb.shell("dd if=/dev/urandom of={} bs=1024 count={}".format(DEVICE_TEMP_FILE, kbytes))
            dev_md5 = adb.shell("md5 {}".format(DEVICE_TEMP_FILE)).split()[0]

            with tempfile.NamedTemporaryFile(mode="w") as tmp_write:
                adb.pull(remote=DEVICE_TEMP_FILE, local=tmp_write.name)
                with open(tmp_write.name) as tmp_read:
                    host_contents = tmp_read.read()
                    host_md5 = compute_md5(host_contents)
                self.assertEqual(dev_md5, host_md5)
        finally:
            adb.shell_nocheck("rm {}".format(device, DEVICE_TEMP_FILE))

if __name__ == '__main__':
    dev_count = get_attached_device_count()
    if dev_count:
        suite = unittest.TestLoader().loadTestsFromName(__name__)
        unittest.TextTestRunner(verbosity=3).run(suite)
    else:
        print "Test suite must be run with attached devices"



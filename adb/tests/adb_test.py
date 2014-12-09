import unittest
import subprocess
import re
import tempfile
import random
import os
import hashlib
import binascii

def call(cmdStr):
    """ Run process and return output tuple (stdout, stderr, ret code) """
    process = subprocess.Popen(cmdStr.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return stdout, stderr, process.returncode

def callChecked(cmdStr):
    """ Run process and get stdout+stderr, raise an exception on trouble """
    return subprocess.check_output(cmdStr.split(), stderr=subprocess.STDOUT)

def callCheckedList(cmdStr):
    return callChecked(cmdStr).split('\n')

def callCheckedListSkip(cmdStr):
    outList = callCheckedList(cmdStr)
    isInitLine = lambda x: (len(x) >= 3) and (x[0] == "*") and (x[-2] == "*")
    return [line for line in outList if not isInitLine(line)]

def getDeviceList(qualifiers = False):
    output = callCheckedListSkip("adb devices")
    devList = []
    for line in output[1:]:
        if line.find("device") != -1:
            devList.append(line.split()[0])
    return devList

def getAttachedDeviceCount():
    return len(getDeviceList())

def computeMd5(string):
    h = hashlib.md5()
    h.update(string)
    return binascii.hexlify(h.digest())

class AdbBasic(unittest.TestCase):
    def setUp(self):
        pass
    def tearDown(self):
        pass
    def test_devices(self):
        """ Get uptime for each device plugged in from /proc/uptime """
        devList = getDeviceList()
        for device in devList:
            out = callChecked("adb -s {} shell cat /proc/uptime".format(device))
            self.assertTrue(len(out.split()) == 2)
            self.assertTrue(float(out.split()[0]) > 0.0)
            self.assertTrue(float(out.split()[1]) > 0.0)

    def test_devices_with_qualifiers(self):
        """ Get uptime for each device plugged in from /proc/uptime """
        devList = getDeviceList(qualifiers=True)
        for device in devList:
            out = callChecked("adb -s {} shell cat /proc/uptime".format(device))
            self.assertTrue(len(out.split()) == 2)
            self.assertTrue(float(out.split()[0]) > 0.0)
            self.assertTrue(float(out.split()[1]) > 0.0)

    def test_help(self):
        """ Make sure we get _something_ out of help """
        out = callChecked("adb help")
        self.assertTrue(len(out) > 0)

    def test_version(self):
        """ Get a version number out of the output of adb """
        out = callChecked("adb version").split()
        versionNum = False
        for item in out:
            if re.match("[\d+\.]*\d", item):
                versionNum = True
        self.assertTrue(versionNum)

class AdbFile(unittest.TestCase):
    def test_push(self):
        """ Push a file to all attached devices """
        with tempfile.NamedTemporaryFile(mode="w") as tmp:
            kbytes = 512
            randStr = os.urandom(1024 * kbytes)
            tmp.write(randStr)
            tmp.flush()

            hostMd5 = computeMd5(randStr)

            devList = getDeviceList()
            for device in devList:
                call("adb -s {} shell rm /data/tmp".format(device))
                try:
                    callChecked("adb -s {} push {} /data/tmp".format(device, tmp.name))
                    deviceMd5 = callChecked("adb -s {} shell md5 /data/tmp".format(device)).split()[0]
                    self.assertEqual(hostMd5, deviceMd5)
                finally:
                    call("adb -s {} shell rm /data/tmp".format(device))

    def test_pull(self):
        """ pull a file from all attached devices """
        devList = getDeviceList()
        kbytes = 512
        for device in devList:
            call("adb -s {} shell rm /data/tmp".format(device))
            try:
                callChecked("adb -s {} shell dd if=/dev/urandom of=/data/tmp bs=1024 count={}".format(device, kbytes))
                deviceMd5 = callChecked("adb -s {} shell md5 /data/tmp".format(device)).split()[0]
                with tempfile.NamedTemporaryFile(mode="w") as tmpWrite:
                    callChecked("adb -s {} pull /data/tmp {}".format(device, tmpWrite.name))
                    with open(tmpWrite.name) as tmpRead:
                        hostContents = tmpRead.read()
                        hostMd5 = computeMd5(hostContents)
                    self.assertEqual(deviceMd5, hostMd5)
            finally:
                call("adb -s {} shell rm /data/tmp".format(device))


if __name__ == '__main__':
    devCount = getAttachedDeviceCount()
    if devCount:
        suite = unittest.TestLoader().loadTestsFromName(__name__)
        unittest.TextTestRunner(verbosity=3).run(suite)
    else:
        print "Test suite must be run with attached devices"



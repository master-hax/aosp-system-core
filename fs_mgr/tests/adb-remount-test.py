#!/usr/bin/env python3
#
# Copyright 2024, The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import os
import re
import subprocess
import sys
import tempfile
from collections import namedtuple
from datetime import datetime

OVERLAYFS_BACKING = ["/cache", "/mnt/scratch"]

MountPoint = namedtuple('MountPoint', ['source', 'target', 'fs_type', 'options'])


class TestError(Exception):
    def __init__(self, message):
        super(Exception, self).__init__(self, message)
        self.message = message


class TestHarness(object):
    def __init__(self, args, tempdir):
        self.args = args
        self.tempdir = tempdir
        self.serial = self.args.serial
        self.can_restore_verity = True
        self.enforcing = True
        self.overlayfs_needed = False


    def run(self):
        self.setup()

        self.log_info("Test starting.")

        # test batch 1 - basic remount functionality
        self.test_disable_verity()
        self.check_kernel_patches()
        self.check_remount_commands()

        self.reset_overlayfs()

        # test batch 2 - remount commands
        self.test_overlayfs_setup_from_scratch()
        self.test_remount_r()
        self.test_readwrite()


    def setup(self):
        if not self.serial:
            devices = self.adb_devices()
            if len(devices) == 0:
                raise TestError("No devices connected to ADB")
            if len(devices) > 1:
                raise TestError("Multiple devices connected to ADB")
            self.serial = devices[0]
            self.log_info("Found device: {}".format(self.serial))

        if self.serial in self.fastboot_devices():
            raise TestError("device in fastboot mode")
        if self.in_recovery():
            raise TestError("device in recovery mode")

        if not self.in_adb():
            self.log_warning("device not in ADB mode")
            self.adb_wait()

        if self.getprop("ro.debuggable") != "1":
            raise TestError("device not a debug build")
        if self.getprop("ro.boot.verifiedbootstate") != "orange":
            raise TestError("device not bootloader unlocked")

        if self.getprop("partition.system.verified") != "2":
            self.log_warning("device might not support verity")
            self.can_restore_verity = False

        if 'Enforcing' not in self.adb_su(["getenforce"]):
            self.log_warning("device is not enforcing sepolicy")
            self.enforcing = False

        build_desc = self.getprop("ro.build.description")
        self.log_info("Build: {}".format(build_desc))

        kernel = self.adb_su(["cat", "/proc/version"])
        self.log_info("Kernel: {}".format(kernel))

        active_slot = self.getprop("ro.boot.slot_suffix")
        self.log_info("Active slot: {}".format(active_slot))

        self.adb_wait()
        self.adb_root()

        self.reset_overlayfs()

        self.overlayfs_needed = self.is_overlayfs_needed()
        self.log_info("overlayfs needed: {}".format(self.overlayfs_needed))

        if self.is_overlayfs_mounted():
            raise TestError("overlay takeover unexpected at this phase")


    def test_disable_verity(self):
        self.log_begin("Test disable-verity -R")

        output, rc = self.try_adb_shell(["disable-verity", "-R"])
        if rc != 0 and rc != 255:
            self.log_error(output)
            raise TestError("disable-verity -R failed")
        
        self.sleep(2)
        self.adb_wait()
        if self.getprop("partition.system.verified") == "2":
            raise TestError("verity not disabled after disable-verity")

        if self.overlayfs_needed:
            if not self.is_overlayfs_mounted():
                raise TestError("no overlays after adb disable-verity -R")
            self.log_ok("overlays present")

        self.log_ok("adb disable-verity -R")


    def check_kernel_patches(self):
        self.adb_root()
        _, rc = self.try_adb_shell(["test", "-d", "/sys/module/overlay"])
        if rc:
            _, rc = self.try_adb_shell(["grep", "-q", "overlay", "/proc/filesystems"])

        if rc != 0:
            self.log_ok("overlay module not present")
            return

        if self.is_overlayfs_mounted():
            path = "/sys/module/overlay/parameters/override_creds"
            _, rc = self.try_adb_shell(["test", "-f", path])
            if rc == 0:
                self.log_ok("overlay module supports override_creds")
            else:
                uname = self.adb_shell(["uname", "-r"])
                parts = uname.split('.')
                major, minor = int(parts[0]), int(parts[1])
                if major > 4 or (major == 4 and minor >= 4):
                    self.log_ok("overlay module uses caller's creds")
                else:
                    raise TestError("overlay module does not support override_creds")


    def check_remount_commands(self):
        self.log_begin("Testing raw remount commands")

        mounts = self.get_mounts()
        system = self.find_mount_point("/system", mounts)
        vendor = self.find_mount_point("/vendor", mounts)

        self.check("ro" in system.options, "system is readonly")
        self.check("ro" in vendor.options, "vendor is readonly")

        self.adb_su(["mount", "-o", "remount,rw", "/vendor"])
        vendor = self.find_mount_point("/vendor")
        self.check("rw" in vendor.options, "vendor is RW")

        self.adb_su(["mount", "-o", "remount,ro", "/vendor"])
        vendor = self.find_mount_point("/vendor")
        self.check("ro" in vendor.options, "vendor is RO")

        self.adb_su(["remount", "vendor"])

        vendor = self.find_mount_point("/vendor")
        self.check("rw" in vendor.options, "vendor is RW after remount vendor")

        system = self.find_mount_point("/system")
        self.check("ro" in system.options, "system is RO after remount vendor")

        self.adb_su(["mount", "-o", "remount,ro", "/vendor"])
        self.log_ok("adb remount vendor")


    def test_overlayfs_setup_from_scratch(self):
        self.log_begin("Testing overlayfs setup from scratch")

        vendor = self.find_mount_point("/vendor")
        self.check("ro" in vendor.options, "vendor is RO")

        self.adb_su(["remount", "vendor"])
        if self.overlayfs_needed:
            vendor = self.find_mount_point("/vendor")
            self.check(vendor.fs_type == "overlay", "vendor is an overlay")

            system = self.find_mount_point("/system")
            self.check(system.fs_type != "overlay", "system is not an overlay")

        vendor = self.find_mount_point("/vendor")
        self.check("rw" in vendor.options, "vendor is RW after remount vendor")

        system = self.find_mount_point("/system")
        self.check("ro" in system.options, "system is RO after remount vendor")

        self.log_ok("adb remount from scratch")


    def test_remount_r(self):
        self.log_begin("Testing adb remount -R")

        output, rc = self.try_adb_shell(["remount", "-R"], root = True)
        if rc != 0 and rc != 255:
            self.log_error(output)
            raise TestError("adb remount -R failed")

        self.sleep(2)
        self.adb_wait()

        self.check(self.getprop("partition.system.verified") != "2",
                   "verify not disabled after adb remount -R")

        if self.overlayfs_needed:
            system = self.find_mount_point("/system")
            self.check(system.fs_type == "overlay", "/system is overlay")

            vendor = self.find_mount_point("/vendor")
            self.check(vendor.fs_type == "overlay", "/vendor is overlay")
        else:
            self.log_warning("reboot to RO (device doesn't use overlayfs)")
            self.adb_reboot()

        self.log_ok("adb remount -R")


    def test_readwrite(self):
        self.log_begin("Testing adb remount RW")

        # Feed log with selinux denials as baseline before overlays
        self.adb_unroot()
        for mount in self.get_partitions():
            if mount.target == "/":
                self.try_adb_shell(["find", "/system"])
            else:
                self.try_adb_shell(["find", mount.target])

        system = self.find_mount_point("/system")
        self.check("ro" in system.options, "/system is RO")

        vendor = self.find_mount_point("/vendor")
        self.check("ro" in vendor.options, "/vendor is RO")


    def check(self, cond, message):
        if not cond:
            raise TestError(message)


    def is_overlayfs_mounted(self):    
        for mount in self.get_mounts():
            if mount.source == 'overlay':
                return True
        return False


    def is_overlayfs_needed(self):
        mounts = self.get_partitions()
        mounts = [mount for mount in mounts if "ro" in mount.options]

        for mount in mounts:
            if mount.fs_type == 'erofs':
                return True
            output = self.adb_shell(["tune2fs", "-l", mount.source])
            if "shared_blocks" in output:
                return True


    def reset_overlayfs(self):
        if self.surgically_wipe_overlayfs() or self.is_overlayfs_mounted():
            self.log_warning("rebooting before test")
            self.adb_reboot()
            self.adb_root()


    def surgically_wipe_overlayfs(self):
        for d in OVERLAYFS_BACKING:
            path = os.path.join(d, "overlay")
            _, rc = self.try_adb_shell(["test", "-d", path], root = True)
            if rc == 0:
                self.log_info("{} is setup, surgically wiping".format(path))
                self.adb_su(["rm", "-rf", path])
                return True
        return False


    def avc_check(self):
        if not self.overlayfs_needed:
            return
        output = self.adb(["logcat", "-b", "all", "-v", "brief", "-d", "-e",
                           "context=u:object_r:unlabeled:s0"])
        avcs = [line for line in output.split('\n') if 'avc: ' in line]
        if avcs:
            self.log_warning("unlabeled sepolicy violations:")
            for avc in avcs:
                self.log_warning(avc)


    def get_partitions(self):
        mounts = []
        for mount in self.get_mounts():
            if not mount.source.startswith('/dev/block/'):
                continue
            if mount.target.startswith('/apex'):
                continue
            if mount.target.startswith('/bootstrap-apex'):
                continue
            if mount.target.startswith('/data'):
                continue
            if mount.target.startswith('/metadata'):
                continue
            if mount.target.startswith('/mnt'):
                continue
            mounts.append(mount)
        return mounts


    def find_mount_point(self, mount_point, mounts = None):
        if not mounts:
            mounts = self.get_mounts()

        # Search backwards for the most recent mount.
        for mount in mounts[::-1]:
            if mount.target == mount_point:
                return mount
            if mount.target in ['/', '/system'] and mount_point == '/system':
                return mount
        return None


    def get_mounts(self):
        output = self.adb(["shell", "cat", "/proc/mounts"])
        mounts = []
        for line in output.split('\n'):
            m = re.match("^(.+)\s+(.+)\s+(.+)\s+(.+)\s+\d+\s+\d+", line)
            if not m:
                continue
            mounts.append(MountPoint(m.group(1), m.group(2), m.group(3),
                                     set(m.group(4).split(','))))
        return mounts


    def cleanup(self):
        self.log_info("Restoring device")
        if self.in_fastboot():
            self.run_process(["fastboot", "-s", self.serial, "reboot"])
            self.adb_wait()

        if not self.in_adb():
            self.log_error("expected ADB device")
            return

        self.adb_root()

        reboot = False
        if self.surgically_wipe_overlayfs():
            reboot = True

        if self.can_restore_verity:
            self.adb(["enable-verity"])
            reboot = True

        if reboot:
            self.adb(["reboot"])


    def adb_reboot(self):
        import time

        self.adb(["reboot", "remount-test"])
        self.sleep(2)
        self.adb_wait()


    def sleep(self, sec):
        import time
        time.sleep(sec)


    def adb_wait(self):
        self.adb(["wait-for-device"], timeout = 4 * 60)
        reason = self.getprop("ro.boot.bootreason")
        if reason and not reason.startswith('reboot'):
            self.log_info("Detected reboot reason: {}".format(reason))


    def adb_unroot(self):
        if self.adb_user() != "root":
            return

        # This can be flaky.
        _, _ = self.test_process(["adb", "-s", self.serial, "unroot"])
        self.sleep(2)
        self.adb(["wait-for-device"], timeout = 4 * 60)
        if self.adb_user() == "root":
            raise TestError("unable to connect to adb as non-root")


    def adb_root(self):
        if self.adb_user() == "root":
            return

        # This can be flaky.
        _, _ = self.test_process(["adb", "-s", self.serial, "root"])
        self.sleep(2)
        self.adb(["wait-for-device"], timeout = 4 * 60)
        if self.adb_user() != "root":
            raise TestError("unable to connect to adb as root")


    def getprop(self, prop):
        val = self.adb(["shell", "getprop", prop])
        return val.strip()


    def adb_user(self):
        output = self.adb(["shell", "echo", "${USER}"])
        return output.strip()


    # Run adb shell, return (output, exitcode). Does not throw.
    def try_adb_shell(self, argv, root = False):
        adb_argv = ["adb", "-s", self.serial, "shell"]
        if root:
            adb_argv += ["su", "root"]
        adb_argv += argv
        return self.test_process(adb_argv)


    def adb_su(self, argv, **kwargs):
        adb_argv = ["shell", "su", "root"] + argv
        return self.adb(adb_argv, **kwargs)


    def adb(self, argv, **kwargs):
        adb_argv = ["adb", "-s", self.serial] + argv
        return self.run_process(adb_argv, **kwargs)

 
    def in_adb(self):
        devices = self.adb_devices()
        return self.serial in devices


    def adb_devices(self):
        output = self.run_process(["adb", "devices"])
        devices = []
        for line in output.split("\n"):
            m = re.match("([A-Za-z0-9:.]+)\s+device", line)
            if not m:
                continue
            devices.append(m.group(1))
        return devices


    def fastboot_devices(self):
        output = self.run_process(["fastboot", "devices"])
        devices = []
        for line in output.split("\n"):
            m = re.match("([A-Za-z0-9:.]+)\s+device", line)
            if not m:
                continue
            devices.append(m.group(1))
        return devices


    def in_recovery(self):
        output = self.run_process(["adb", "devices"])
        devices = []
        for line in output.split("\n"):
            m = re.match("([A-Za-z0-9:.]+)\s+recovery", line)
            if not m:
                continue
            if m.group(1) == self.serial:
                return True
        return False


    # Run a process, throw on error.
    def run_process(self, argv, **kwargs):
        output, rc = self.test_process(argv, **kwargs)

        if rc is None:
            raise TestError("timed out")
        elif rc != 0:
            if output:
                self.log_error(output)
            raise TestError("process failed")

        return output


    # Run a process, log 
    def test_process(self, argv, **kwargs):
        self.log_process(argv)

        try:
            output = subprocess.check_output(argv, stderr = subprocess.STDOUT, **kwargs)
            rc = 0
        except subprocess.TimeoutExpired as e:
            output = e.output
            rc = None
        except subprocess.CalledProcessError as e:
            output = e.output
            rc = e.returncode

        if output is None:
            output = b''

        if rc is None:
            self.log_info("Return code: timed out")
        elif rc != 0:
            self.log_info("Return code: {}".format(rc))
        return self.decode_text(output), rc


    def log_process(self, argv):
        argv_text = [arg if " " not in arg else "\"{}\"".format(arg) for arg in argv]
        argv_text = " ".join(argv_text)
        self.log_info("Running: {}".format(argv_text))


    def decode_text(self, data):
        try:
            if sys.stdout.encoding:
                return data.decode(sys.stdout.encoding, 'replace')
        except:
            pass

        try:
            import locale
            return data.decode(locale.getpreferredencoding(), 'replace')
        except:
            pass

        return data.decode('utf-8', 'replace')


    def log_begin(self, message):
        self.log_impl("\033[32m", "[ TEST     ]", message)


    def log_ok(self, message):
        self.log_impl("\033[32m", "[       OK ]", message)


    def log_warning(self, message):
        self.log_impl("\033[33m", "[  WARNING ]", message)


    def log_info(self, message):
        self.log_impl("\033[34m", "[     INFO ]", message)


    def log_error(self, message):
        self.log_impl("\033[31m", "[    ERROR ]", message)


    def log_impl(self, color, tag, message):
        for line in message.split("\n"):
            if self.args.print_time:
                time = datetime.now().strftime("%m-%d %H:%M:%S")
                sys.stdout.write(time)
                sys.stdout.write(" ")
            if self.args.print_color and color:
                sys.stdout.write(color)
            sys.stdout.write(tag)
            if self.args.print_color and color:
                sys.stdout.write("\033[0m")
            sys.stdout.write(" ")
            sys.stdout.write(line)
            sys.stdout.write("\n")
            sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--print-color", action = "store_true", default = sys.stdout.isatty(),
                        help = "Dress output with highlighting colors")
    parser.add_argument("-t", "--print-time", action = "store_true", default = False,
                        help = "Report the test duration")
    parser.add_argument("-D", "--no-wait-screen", action = "store_true", default = False,
                        help = "Do not wait for display screen to settle")
    parser.add_argument("-s", "--serial", type = str,
                        help = "Specify device (must if multiple are present)")
    parser.add_argument("-a", "--wait-adb", type = int, help = "adb wait timeout, in seconds")
    parser.add_argument("-f", "--wait-fastboot", type = int,
                        help = "fastboot wait timeout, in seconds")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tempdir:
        harness = TestHarness(args, tempdir)
        try:
            harness.run()
        except TestError as e:
            harness.log_error(e.message)
            raise
        finally:
            try:
                harness.cleanup()
            except:
                pass

if __name__ == "__main__":
    main()

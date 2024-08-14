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

MountPoint = namedtuple('MountPoint', ['source', 'target', 'fs_type', 'options'])
DeviceTimeout = 4 * 60


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
        self.overlayfs_backing = ["/mnt/scratch"]

        # Test state
        self.hello_text = None
        self.system_inode = None


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
        self.test_auto_remount()
        self.test_remount_rw()
        self.test_push_content()
        self.flash_vendor()


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

        self.check(self.getprop("ro.debuggable") == "1", "device is a debug build")
        self.check(self.getprop("ro.boot.verifiedbootstate") == "orange",
                   "device bootloader unlocked")

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

        if self.find_mount_point("/cache"):
            self.overlayfs_backing = ["/cache"] + self.overlayfs_backing

        self.reset_overlayfs()

        self.overlayfs_needed = self.is_overlayfs_needed()
        self.log_info("overlayfs needed: {}".format(self.overlayfs_needed))

        self.check(not self.is_overlayfs_mounted(), "overlay takeover unexpected at this phase")


    def test_disable_verity(self):
        self.log_begin("Test disable-verity -R")

        output, rc = self.try_adb_shell(["disable-verity", "-R"])
        if rc != 0 and rc != 255:
            self.log_error(output)
            raise TestError("disable-verity -R failed")

        self.sleep(2)
        self.adb_wait()
        self.check(self.getprop("partition.system.verified") != "2",
                   "verity not disabled after disable-verity")

        if self.overlayfs_needed:
            self.check(self.is_overlayfs_mounted(), "no overlays after adb disable-verity -R")
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


    def test_auto_remount(self):
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


    def test_remount_rw(self):
        self.log_begin("Testing adb remount RW")

        # Feed log with selinux denials as baseline before overlays
        self.adb_unroot()
        self.feed_selinux_denials()

        self.adb_root()

        old_mounts = self.get_mounts()
        system = self.find_mount_point("/system", old_mounts)
        self.check("ro" in system.options, "/system is RO")

        vendor = self.find_mount_point("/vendor", old_mounts)
        self.check("ro" in vendor.options, "/vendor is RO")

        # Already remount -R'd earlier.
        self.adb_shell(["remount"])

        new_mounts = self.get_mounts()
        for mount in new_mounts:
            if mount.fs_type == "overlay":
                self.check("rw" in mount.options, "{} is rw".format(mount.target))
                self.check("noatime" in mount.options, "{} is noatime".format(mount.target))

        for d in self.overlayfs_backing:
            path = os.path.join(d, "overlay", "system", "upper")
            _, rc = self.try_adb_shell(["test", "-d", path])
            if rc == 0:
                self.log_info("overlayfs set up at: {}".format(path))

        self.log_ok("adb remount RW")


    def test_push_content(self):
        self.log_begin("Push content to partitions")

        self.adb_root()

        self.hello_text = "Hello world! " + datetime.now().strftime("%m-%d %H:%M:%S")
        with tempfile.NamedTemporaryFile(dir = self.tempdir) as fp:
            fp.write(self.hello_text.encode("utf-8"))
            fp.flush()

            dirs = [part.target for part in self.get_partitions()]
            dirs += ["/system/priv-app"]
            for path in dirs:
                hello_path = os.path.join(path, "hello")
                self.adb(["push", fp.name, hello_path])
                output = self.adb_shell(["cat", hello_path])
                self.check(output == self.hello_text, "{} contains pushed file".format(hello_path))

        # Check that the inodes are different
        self.system_inode = self.adb_shell(["stat", "--format=%i", "/system/hello"])
        vendor_inode = self.adb_shell(["stat", "--format=%i", "/vendor/hello"])
        self.check(self.system_inode != vendor_inode, "pushed files have different inodes")

        build_prop_original_path = os.path.join(self.tempdir, "system_build.prop.original")
        build_prop_modified_path = os.path.join(self.tempdir, "system_build.prop.modified")
        build_prop_device_path = os.path.join(self.tempdir, "system_build.prop.device")

        self.adb(["pull", "/system/build.prop", build_prop_original_path])
        with open(build_prop_original_path, "rt") as fp:
            build_prop_original = fp.read()
        with open(build_prop_modified_path, "wt") as fp:
            fp.write(build_prop_original)
            fp.write("\n")
            fp.write("# Properties added by adb remount test\n")
            fp.write("test.adb.remount.system.build.prop=true\n")
        self.adb(["push", build_prop_modified_path, "/system/build.prop"])
        self.adb(["pull", "/system/build.prop", build_prop_device_path])

        with open(build_prop_device_path, "rt") as fp:
            build_prop_device = fp.read()
        with open(build_prop_modified_path, "rt") as fp:
            build_prop_modified = fp.read()
        self.check(build_prop_device == build_prop_modified,
                   "/system/build.prop matches pushed")

        self.log_ok("Push content to partitions")
        self.log_begin("Reboot to confirm content persistence")

        self.adb_reboot(fixup_recovery = True)

        if self.overlayfs_needed and not self.is_overlayfs_mounted():
            raise TestError("no overlays after reboot")

        self.adb_unroot()

        if self.enforcing:
            output, rc = self.try_adb_shell(["cat", "/vendor/hello"])
            self.check(rc != 0, "no permission to access /vendor/hello")
            self.check("cat: /vendor/hello: Permission denied" in output,
                       "no permission to access /vendor/hello")

            # feed log with selinux denials again
            self.feed_selinux_denials()

        # If overlayfs has a nested security problem, this will fail.
        self.adb_shell(["ls", "/system"])
        self.adb_shell(["test", "-d", "/system/priv-app"])
        output = self.adb_shell(["cat", "/system/priv-app/hello"])
        self.check(output == self.hello_text, "priv-app matches after reboot")

        # Only root can read vendor if sepolicy permissions are as expected.
        self.adb_root()
        for mount in self.get_partitions():
            path = os.path.join(mount.target, "hello")
            output = self.adb_shell(["cat", path])
            self.check(output == self.hello_text, "{} matches after reboot".format(path))

        self.check(self.adb_shell(["stat", "--format=%i", "/system/hello"]) == self.system_inode,
                   "system inode is unchanged after reboot")
        self.check(self.adb_shell(["stat", "--format=%i", "/vendor/hello"]) == vendor_inode,
                   "vendor inode is unchanged after reboot")

        self.feed_selinux_denials()

        # Check the updated build prop after reboot.
        self.check(self.getprop("test.adb.remount.system.build.prop") == "true",
                   "modified build prop is true")

        self.adb(["pull", "/system/build.prop", build_prop_device_path])
        with open(build_prop_device_path, "rt") as fp:
            build_prop_device = fp.read()
        self.check(build_prop_device == build_prop_modified,
                   "/system/build.prop content remains after reboot")

        self.log_ok("Content persists after reboot")


    def flash_vendor(self):
        device = self.getprop("ro.product.vendor.device")
        if "emulator_" in device or "emulator64_" in device:
            self.log_warning("{} does not support fastboot, skipping".format(device))

        self.adb_root()

        vendor_img = os.path.join(self.tempdir, "vendor.img")

        slot_suffix = self.getprop("ro.boot.slot_suffix")
        _, rc = self.test_process(["adb", "-s", self.serial, "pull",
                                   "/dev/block/mapper/vendor{}".format(slot_suffix),
                                   vendor_img])
        if rc == 0:
            dynamic_partitions = True
        else:
            _, rc = self.test_process(["adb", "-s", self.serial, "pull",
                                       "/dev/block/by-name/vendor{}".format(slot_suffix)])
            if rc != 0:
                raise TestError("could not locate vendor partition on device")
            dynamic_partitions = False

        self.avc_check()
        if dynamic_partitions:
            self.adb(["reboot", "fastboot"])
            self.check("yes" in self.fastboot(["getvar", "is-userspace"]), "in fastbootd")
        else:
            self.adb(["reboot", "bootloader"])

        self.fastboot(["flash", "vendor", vendor_img])
        self.fastboot(["reboot"])
        self.adb_wait(fixup_recovery = True)

        if self.overlayfs_needed:
            system = self.find_mount_point("/system")
            self.check(system.fs_type == "overlay", "/system should still overlay")
            vendor = self.find_mount_point("/vendor")
            self.check(vendor.fs_type != "overlay", "/vendor overlay should be gone")

        output = self.adb(["cat", "/system/hello"])
        self.check(output == self.hello_text, "/system content same after flash vendor")
        self.check(self.adb_shell(["stat", "--format=%i", "/system/hello"]) == self.system_inode,
                   "system inode is unchanged after flash vendor")


    def feed_selinux_denials(self):
        find_argv = ["find"] + [mp.target for mp in self.get_partitions()]
        self.try_adb_shell(find_argv, verbose = False)


    def check(self, cond, message):
        if not cond:
            raise TestError("check failed: {}".format(message))


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
        for d in self.overlayfs_backing:
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
        output = self.adb_shell(["cat", "/proc/mounts"])
        mounts = []
        for line in output.split('\n'):
            m = re.match("^(.+)\s+(.+)\s+(.+)\s+(.+)\s+\d+\s+\d+", line)
            if not m:
                continue
            target = m.group(2)
            if target == "/":
                target= "/system"
            mounts.append(MountPoint(m.group(1), target, m.group(3), set(m.group(4).split(','))))
        return mounts


    def cleanup(self):
        self.log_info("Restoring device")
        if self.serial in self.fastboot_devices():
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
        self.log_ok("Device restored")


    def adb_reboot(self, fixup_recovery = False):
        import time

        try:
            self.adb(["reboot", "remount-test"])
            self.sleep(2)
            self.adb_wait()
        except:
            if self.in_recovery():
                self.adb(["reboot"])
                self.adb_wait()


    def sleep(self, sec):
        import time
        time.sleep(sec)


    def adb_wait(self, fixup_recovery = False):
        self.adb(["wait-for-device"], timeout = DeviceTimeout)
        reason = self.getprop("ro.boot.bootreason")
        if reason and not reason.startswith('reboot'):
            self.log_info("Detected reboot reason: {}".format(reason))
        if self.in_recovery():
            self.adb(["reboot"])
            self.adb_wait()


    def adb_unroot(self):
        if self.adb_user() != "root":
            return

        # This can be flaky.
        _, _ = self.test_process(["adb", "-s", self.serial, "unroot"])
        self.sleep(2)
        self.adb(["wait-for-device"], timeout = DeviceTimeout)
        if self.adb_user() == "root":
            raise TestError("unable to connect to adb as non-root")


    def adb_root(self):
        if self.adb_user() == "root":
            return

        # This can be flaky.
        _, _ = self.test_process(["adb", "-s", self.serial, "root"])
        self.sleep(2)
        self.adb(["wait-for-device"], timeout = DeviceTimeout)
        if self.adb_user() != "root":
            raise TestError("unable to connect to adb as root")


    def getprop(self, prop):
        val = self.adb_shell(["getprop", prop])
        return val.strip()


    def adb_user(self):
        output = self.adb_shell(["echo", "${USER}"])
        return output.strip()


    def adb_su(self, argv):
        return self.adb_shell(argv, root = True)


    # Run adb shell, return (output, exitcode). Does not throw.
    def try_adb_shell(self, argv, root = False, **kwargs):
        adb_argv = ["adb", "-s", self.serial, "shell"]
        if root:
            adb_argv += ["su", "root"]
        adb_argv += argv
        return self.test_process(adb_argv, **kwargs)


    def adb_shell(self, argv, root = False):
        adb_argv = ["adb", "-s", self.serial, "shell"]
        if root:
            adb_argv += ["su", "root"]
        adb_argv += argv
        return self.run_process(adb_argv)


    def adb(self, argv, **kwargs):
        adb_argv = ["adb", "-s", self.serial] + argv
        return self.run_process(adb_argv, **kwargs)


    def fastboot(self, argv, **kwargs):
        serial = self.serial
        if "." in serial or ":" in serial:
            serial = "tcp:" + serial
        fastboot_argv = ["fastboot", "-s", serial] + argv
        return self.run_process(fastboot_argv, **kwargs)


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


    # Run a process, return (output, exitcode).
    def test_process(self, argv, **kwargs):
        self.log_process(argv)
        verbose = kwargs.pop('verbose', True)

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

        if verbose:
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
        except KeyboardInterrupt as e:
            pass
        finally:
            try:
                harness.cleanup()
            except Exception as e:
                harness.log_error(e.message)

if __name__ == "__main__":
    main()

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
import re
import subprocess


__all__ = [
    'AndroidDevice',
    'get_devices',
]


def get_devices():
    out = subprocess.check_output(['adb', 'devices']).splitlines()

    # The first line of `adb devices` just says "List of attached devices", so
    # skip that.
    devices = []
    for line in out[1:]:
        if not line.strip():
            continue
        if 'offline' in line:
            continue

        serial, _ = re.split(r'\s+', line, maxsplit=1)
        devices.append(serial)
    return devices


class AndroidDevice(object):
    def __init__(self, device=None, out_dir=None):
        self.device = device
        self.out_dir = out_dir
        self.adb_cmd = ['adb']
        if self.device is not None:
            self.adb_cmd.extend(['-s', device])
        if self.out_dir is not None:
            self.adb_cmd.extend(['-p', out_dir])

    def _make_shell_cmd(self, user_cmd):
        # Follow any shell command with `; echo; echo $?` to get the exist
        # status of a program since this isn't propagated by adb.
        #
        # The leading newline is needed because `printf 1; echo $?` would print
        # "10", and we wouldn't be able to distinguish the exit code.
        return self.adb_cmd + ['shell'] + user_cmd + ['; echo "\n$?"']

    def _parse_shell_output(self, out):  # pylint: disable=no-self-use
        search_text = out
        max_result_len = len('\r\n255\r\n')
        if len(search_text) > max_result_len:
            # We don't want to regex match over massive amounts of data when we
            # know the part we want is right at the end.
            search_text = search_text[-max_result_len:]
        m = re.search(r'(\r?\n\d+\r?\n)$', search_text)
        if m is None:
            raise RuntimeError('Could not find exit status in shell output.')

        result_text = m.group(1)
        result = int(result_text.strip())
        out = out[:-len(result_text)]  # Trim the result text from the output.
        return result, out

    def _simple_call(self, cmd):
        return subprocess.check_output(
            self.adb_cmd + cmd, stderr=subprocess.STDOUT)

    def shell(self, cmd):
        cmd = self._make_shell_cmd(cmd)
        out = subprocess.check_output(cmd)
        rc, out = self._parse_shell_output(out)
        if rc != 0:
            error = subprocess.CalledProcessError(rc, cmd)
            error.out = out
            raise error
        return out

    def shell_nocheck(self, cmd):
        cmd = self._make_shell_cmd(cmd)
        p = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, _ = p.communicate()
        return self._parse_shell_output(out)

    def install(self, filename):
        return self._simple_call(['install', filename])

    def push(self, local, remote):
        return self._simple_call(['push', local, remote])

    def pull(self, remote, local):
        return self._simple_call(['pull', remote, local])

    def sync(self, directory=None):
        cmd = ['sync']
        if directory is not None:
            cmd.append(directory)
        return self._simple_call(cmd)

    def forward(self, local, remote):
        return self._simple_call(['forward', local, remote])

    def tcpip(self, port):
        return self._simple_call(['tcpip', port])

    def usb(self):
        return self._simple_call(['usb'])

    def root(self):
        return self._simple_call(['root'])

    def unroot(self):
        return self._simple_call(['unroot'])

    def forward_remove(self, local):
        return self._simple_call(['forward', '--remove', local])

    def forward_remove_all(self):
        return self._simple_call(['forward', '--remove-all'])

    def connect(self, host):
        return self._simple_call(['connect', host])

    def disconnect(self, host):
        return self._simple_call(['disconnect', host])

    def reverse(self, remote, local):
        return self._simple_call(['reverse', remote, local])

    def reverse_remove_all(self):
        return self._simple_call(['reverse', '--remove-all'])

    def reverse_remove(self, remote):
        return self._simple_call(['reverse', '--remove', remote])

    def wait(self):
        return self._simple_call(['wait-for-device'])

    def get_prop(self, prop_name):
        output = self.shell(['getprop', prop_name])
        if len(output) != 1:
            raise RuntimeError('Too many lines in getprop output:\n' +
                               '\n'.join(output))
        value = output[0]
        if not value.strip():
            return None
        return value

    def set_prop(self, prop_name, value):
        self.shell(['setprop', prop_name, value])

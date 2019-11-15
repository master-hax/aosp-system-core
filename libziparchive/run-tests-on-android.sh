#!/bin/bash

# Copy the current binaries & tests across.
adb sync
adb push cli-tests /data/nativetest/ziptool/
exec adb shell cli-test /data/nativetest/ziptool/*.test

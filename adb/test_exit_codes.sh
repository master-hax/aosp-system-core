#!/bin/bash

#
# Copyright (C) 2014 The Android Open Source Project
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
#
# Stress out adb connections, making sure exit codes work.
#
# Note that if you get protocol fault messages, this may be a limitation in ADB anyway,
# as this has been observed even without the patch that introduces exit code returning.

echo "Tests that failed will appear below:"

function test_exit_code() {
  $1
  RETURN_CODE="$?"
  if [ "$RETURN_CODE" != "$2" ]; then
    echo "Testing $1 FAILED $RETURN_CODE $2"
  fi
}

test_exit_code "adb shell exit 0" "0" &
test_exit_code "adb shell exit 1" "1" &
test_exit_code "adb shell exit 100" "100" &
test_exit_code "adb shell exit 255" "255" &
test_exit_code "adb shell exit 256" "0" &
test_exit_code "adb shell exit 260" "4" &
test_exit_code "adb shell exit 512" "0" &
test_exit_code "adb shell exit 514" "2" &
test_exit_code "adb shell true" "0" &
test_exit_code "adb shell false" "1" &

for i in `seq 0 255`; do
  test_exit_code "adb shell exit $i" "$i" &
done

test_exit_code "adb shell exit 0" "0" &
test_exit_code "adb shell exit 1" "1" &
test_exit_code "adb shell exit 100" "100" &
test_exit_code "adb shell exit 255" "255" &
test_exit_code "adb shell exit 256" "0" &
test_exit_code "adb shell exit 260" "4" &
test_exit_code "adb shell exit 512" "0" &
test_exit_code "adb shell exit 514" "2" &
test_exit_code "adb shell true" "0" &
test_exit_code "adb shell false" "1" &

wait

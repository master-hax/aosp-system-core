#!/bin/bash

###############################################################################
# This is a helper script intended for Cuttlefish. It tests each supported
# configuration of vts_libsnapshot_test. It is run on presubmit and should be
# run manually after material changes to libsnapshot.
#
# This script is not intended to be run on real devices. For devices under
# test, use vts_libsnapshot_test, which only tests the device's actual shipping
# configuration.
###############################################################################

# Detect host or AOSP.
set -e
set -x
adb root
adb sync data
set +x
set +e

testpath64="/data/nativetest64/vts_libsnapshot_test/vts_libsnapshot_test"
testpath32="/data/nativetest/vts_libsnapshot_test/vts_libsnapshot_test"
if [ -f "${ANDROID_PRODUCT_OUT}/${testpath64}" ]; then
    testpath="${testpath64}"
elif [ -f "${ANDROID_PRODUCT_OUT}/${testpath32}" ]; then
    testpath="${testpath32}"
else
    echo "ERROR: vts_libsnapshot_test not found." 1>&2
    echo "Make sure to build vts_libsnapshot_test or snapshot_tests first." 1>&2
    exit 1
fi

# Verbose, error on failure.
set -x
set -e

echo "Testing VAB with userspace snapshots"
time adb shell ${testpath}

echo "Testing VAB with dm-snapshot and compression"
time adb shell ${testpath} -force_mode vabc-legacy

echo "Testing VAB with dm-snapshot"
time adb shell ${testpath} -force_mode vab-legacy

echo "Testing VAB with userspace snapshots and no compression"
time adb shell ${testpath} -compression_method none

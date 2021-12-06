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

# Verbose, error on failure.
set -x
set -e

testpath=/data/local/tests/unrestricted/run_snapshot_tests/vts_libsnapshot_test

echo "Testing VAB with userspace snapshots"
time adb shell ${testpath}

echo "Testing VAB with dm-snapshot and compression"
time adb shell ${testpath} -force_mode vabc-legacy

echo "Testing VAB with dm-snapshot"
time adb shell ${testpath} -force_mode vab-legacy

echo "Testing VAB with userspace snapshots and no compression"
time adb shell ${testpath} -compression_method none

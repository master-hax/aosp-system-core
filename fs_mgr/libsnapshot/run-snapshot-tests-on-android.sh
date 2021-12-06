#!/bin/bash

###############################################################################
# This is a helper script intended for Cuttlefish. It tests non-default
# supported configurations of vts_libsnapshot_test. It is run on presubmit.
#
# This script is not intended to be run on real devices. For devices under
# test, use vts_libsnapshot_test, which only tests the device's actual shipping
# configuration.
###############################################################################

# Verbose, error on failure.
set -x
set -e

testpath=/data/local/tests/unrestricted/run_snapshot_tests/vts_libsnapshot_test

echo "Testing VAB with snapuserd and compression"
time adb shell ${testpath} -compression_method gz

# For testing other modes, we don't need to include the (expensive) ImageManager
# tests which have no dependencies on snapuserd/dm-snapshot. This shaves a few
# minutes off test runtime.
exclude_heavy="--gtest_filter=-ImageManagerTest/*"

echo "Testing VAB with dm-snapshot and compression"
time adb shell ${testpath} -force_mode vabc-legacy ${exclude_heavy}

echo "Testing VAB with dm-snapshot"
time adb shell ${testpath} -force_mode vab-legacy ${exclude_heavy}

# For testing other forms of compression, we don't need to run through every
# test. Just test the essentials.
essential="--gtest_filter=SnapshotUpdateTest.FullUpdateFlow"

echo "Testing VAB with userspace snapshots and no compression"
time adb shell ${testpath} -compression_method none ${essential}

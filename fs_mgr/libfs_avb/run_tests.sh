#!/bin/sh
#
# Run host tests
atest --host libfs_avb_test            # Tests public libfs_avb APIs.
atest --host libfs_avb_internal_test   # Tests libfs_avb private APIs.

# Run device tests
atest libfs_avb_device_test            # Test public libfs_avb APIs on a device.

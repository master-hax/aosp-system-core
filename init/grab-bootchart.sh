#!/bin/sh
#
# this script is used to retrieve the bootchart log generated
# by init when compiled with INIT_BOOTCHART=true.
#
# All options are passed to adb, these options make sense:
#
# -d                        - directs command to the only connected USB device
#                             returns an error if more than one USB device is
#                             present.
# -e                        - directs command to the only running emulator.
#                             returns an error if more than one emulator is
#                             running.
# -s <specific device>      - directs command to the device or emulator with
#                             the given serial number or qualifier.
# -p <product name or path> - simple product name like 'sooner', or a
#                             relative/absolute path to a product out directory
#                             like 'out/target/product/sooner'.
# -H                        - Name of adb server host (default: localhost)
# -P                        - Port of adb server (default: 5037)
#
# environmental variables:
#   ANDROID_SERIAL          - The serial number to connect to. -s takes
#                             priority over this if given.
#   ANDROID_PRODUCT_OUT     - absolute product name path. -p takes priority
#                             over this if given.
#
# for all details, see //device/system/init/README.BOOTCHART
#
TMPDIR=/tmp/android-bootchart
rm -rf $TMPDIR
mkdir -p $TMPDIR

LOGROOT=/data/bootchart
TARBALL=bootchart.tgz

FILES="header proc_stat.log proc_ps.log proc_diskstats.log kernel_pacct"

for f in $FILES; do
    adb "${@}" pull $LOGROOT/$f $TMPDIR/$f 2>&1 > /dev/null
done
(cd $TMPDIR && tar -czf $TARBALL $FILES)
cp -f $TMPDIR/$TARBALL ./$TARBALL
echo "next step: bootchart ./${TARBALL}"

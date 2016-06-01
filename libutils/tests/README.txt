One way to run these tests:

Build the rest of the tree as usual; then "mma -j<whatever>" in this directory

Install on device, possibly with "adb root; adb remount; adb sync"

Use "adb shell" followed by
"/data/nativetest/libutils_tests/libutils_tests" on the device.

There may be another, better way ...

The RefBase RacingDestructors test may take a long time on a uniprocessor
due to excessive context switching.

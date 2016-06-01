Run device tests:

mma -j<whatever>
(after adb disable-verity; adb reboot)
adb root
adb remount
adb sync
adb shell /data/nativetest/libutils_tests/libutils_tests

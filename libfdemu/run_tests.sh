#!/bin/bash

set -e


echo "Running Linux x86 tests"
$ANDROID_HOST_OUT/nativetest/libfdemu_test/libfdemu_test

echo "Running Linux x86-64 tests"
$ANDROID_HOST_OUT/nativetest64/libfdemu_test/libfdemu_test

TMPDIR=`mktemp -d`
echo "Running Windows x86 tests"
mkdir "$TMPDIR/win32"
cd "$TMPDIR/win32"
cp $ANDROID_HOST_OUT/../windows-x86/nativetest/libfdemu_test/libfdemu_test.exe .
cp $ANDROID_BUILD_TOP/prebuilts/gcc/linux-x86/host/x86_64-w64-mingw32-4.8/x86_64-w64-mingw32/lib32/libwinpthread-1.dll .
wine libfdemu_test.exe

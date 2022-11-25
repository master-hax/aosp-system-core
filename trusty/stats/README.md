# Development Notes

## Android build

```
$ source build/envsetup.sh
$ lunch qemu_trusty_arm64-userdebug
$ m
```

## Trusty build

```
$ ./trusty/vendor/google/aosp/scripts/build.py qemu-generic-arm64-test-debug --skip-test 2>stderr.log
```

## Trusty PORT_TEST

```
$ ./build-root/build-qemu-generic-arm64-test-debug/run --headless --boot-test "com.android.trusty.stats.test" --verbose
```

## Android Native Test

```
$ ./build-root/build-qemu-generic-arm64-test-debug/run --headless --android /usr/local/google/home/armellel/depot/android/aosp --shell-command "/data/nativetest64/vendor/trusty_stats_test/trusty_stats_test" --verbose
```

## Trusty Backtrace analysis

```
$ export A2L=./prebuilts/clang/host/linux-x86/llvm-binutils-stable/llvm-addr2line
$ export OD=./prebuilts/clang/host/linux-x86/llvm-binutils-stable/llvm-objdump
$ $OD -d -C build-root/build-qemu-generic-arm64-test-debug/user_tasks/trusty/user/base/app/metrics/metrics.syms.elf > objdump.lst
$ $A2L -e build-root/build-qemu-generic-arm64-test-debug/user_tasks/trusty/user/base/app/metrics/metrics.syms.elf 0xe5104
```

## Android sync & build


1. sync `git_master`

    ```
    $ repo init -c -u sso://googleplex-android/platform/manifest -b master
    --use-superproject --partial-clone --partial-clone-exclude=platform/frameworks/base --clone-filter=blob:limit=10M
    $ repo sync -c -j$(nproc)
    $ source build/envsetup.sh
    $ lunch <your_device>-userdebug
    $ m
    ```

2. sync the `trusty-metrics-nw` hashtags from aosp


    ```
    $ ./repo_pull.py pull "hashtag:trusty-metrics-nw status:open" -g https://android-review.googlesource.com
-b $BRANCH_NAME
    ```


3. sync the `trusty-metrics-pixel` hashtags from googleplex

    * pixelatoms changes
    * device mk changes for devices
    * pixel metricsd in vendor/google/trusty/common changes)

    ```
    $ ./repo_pull.py pull "hashtag:trusty-metrics-pixel status:open" -g https://googleplex-android-review.googlesource.com
-b $BRANCH_NAME
    ```


3. build

    ```
    $ source build/envsetup.sh
    $ lunch <your_device>-userdebug
    $ m
    ```

## Trusty sync and build

1. sync polygon master

    ```
    $ repo init -u sso://googleplex-polygon-android.googlesource.com/trusty/manifest --partial-clone --clone-filter=blob:limit=10M -b master
    $ ./trusty/vendor/google/polygon/scripts/build.py cloudripper-test-debug 2>stderr.log
    ```

2. `repo_pull` command

    ```
    $ ./repo_pull.py pull "hashtag:trusty-metrics status:open" -g https://android-review.googlesource.com
-b $BRANCH_NAME
    ```

3. build

    ```
    $ ./trusty/vendor/google/aosp/scripts/build.py qemu-generic-arm64-test-debug --skip-test 2>stderr.log
    ```

## Trusty PORT_TEST


on QEmu:

    ```
    $ ./build-root/build-qemu-generic-arm64-test-debug/run --headless --boot-test "com.android.trusty.stats.test" --verbose
    ```

on device:

    ```
    $ /vendor/bin/trusty-ut-ctrl -D /dev/trusty-ipc-dev0 "com.android.trusty.stats.test"
    ```

In a loop:

    ```
    $ ./build-root/build-qemu-generic-arm64-test-debug/run --android /usr/local/google/home/armellel/depot/android/aosp  --verbose
    ```

    ```
    #!/system/bin/sh
    $x = 0
    while(true)
    do
    echo "########################stats.test $x " $(( x++ ));
    /vendor/bin/trusty-ut-ctrl -D /dev/trusty-ipc-dev0 "com.android.trusty.stats.test"
    done
    ```

    ```
    $ adb wait-for-device
    $ adb -s xxxx push metrics.sh /data/user/test/metrics.sh
    $ adb -s xxxx shell sh /data/user/test/metrics.sh
    ```
## Android Native Test


    ```
    $ ./build-root/build-qemu-generic-arm64-test-debug/run --headless --android /usr/local/google/home/armellel/depot/android/aosp --shell-command "/data/nativetest64/vendor/trusty_stats_test/trusty_stats_test" --verbose
    ```

In a loop:

    ```
    #!/system/bin/sh
    $x = 0
    while(true)
    do
    echo "########################stats.test $x " $(( x++ ));
    /data/nativetest64/vendor/trusty_stats_test/trusty_stats_test
    done
    ```

    ```
    $ adb wait-for-device
    $ adb -s xxxx push metrics_nw.sh /data/user/test/metrics_nw.sh
    $ adb -s xxxx shell sh /data/user/test/metrics_nw.sh
    ```

## Trusty Backtrace analysis


    ```
    $ export A2L=./prebuilts/clang/host/linux-x86/llvm-binutils-stable/llvm-addr2line
    $ export OD=./prebuilts/clang/host/linux-x86/llvm-binutils-stable/llvm-objdump
    $ $OD -d -C build-root/build-qemu-generic-arm64-test-debug/user_tasks/trusty/user/base/app/metrics/metrics.syms.elf > objdump.lst
    $ $A2L -e build-root/build-qemu-generic-arm64-test-debug/user_tasks/trusty/user/base/app/metrics/metrics.syms.elf 0xe5104
    ```

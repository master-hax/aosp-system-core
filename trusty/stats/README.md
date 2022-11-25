# Development Notes

*    First get [repo_pull.py and gerrit.py](https://android.googlesource.com/platform/development/+/master/tools/repo_pull/) from aosp.

*    Although this repo is not currently in Trusty’s manifest, it’s sufficient to copy these two python scripts to the root of the Trusty project and run them from there. Make sure to follow the [repo_pull installation](https://android.googlesource.com/platform/development/+/master/tools/repo_pull/#installation) steps if necessary.

## Android sync & build


1. sync `aosp-master-with-phones`

    ```
    $ repo init -c -u sso://googleplex-android/platform/manifest -b aosp-master-with-phones --use-superproject --partial-clone --partial-clone-exclude=platform/frameworks/base --clone-filter=blob:limit=10M
    $ repo sync -c -j$(nproc)
    ```

2. sync the `trusty-metrics-nw` hashtags


    ```
    $ cd .repo/manifests
    $ git checkout -n $BRANCH_NAME
    $ git fetch https://android.googlesource.com/platform/manifest refs/changes/65/2317065/1 && git cherry-pick FETCH_HEAD
    $ git branch --set-upstream-to=origin/aosp-master-with-phones
    $ cd ../..
    $ repo sync -c -j$(nproc) -m default.xml
    $ ./repo_pull.py pull “hashtag:trusty-metrics-nw” -g https://android-review.googlesource.com
-b $BRANCH_NAME
    ```


3. build

    ```
    $ source build/envsetup.sh
    $ lunch qemu_trusty_arm64-userdebug
    $ m
    ```

## Trusty sync and build

1. sync aosp master

    ```
    $ repo init -u sso://android.googlesource.com/trusty/manifest -b master
    ```

2. `repo_pull` command

    ```
    $ cd .repo/manifests
    $ git fetch https://android.googlesource.com/trusty/manifest refs/changes/92/2319592/2 && git checkout FETCH_HEAD -b $BRANCH_NAME
    $ git branch --set-upstream-to=origin/master
    $ cd ../..
    $ repo sync -c -j$(nproc) -m default.xml
    $ ./repo_pull.py pull “hashtag:trusty-metrics” -g https://android-review.googlesource.com
-b $BRANCH_NAME
    ```

3. build

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

# cast-auth hal build and test instructions

## Android project setup

Get an android aosp project (choose `tm-dev` branch) with following CLs.

```
$ mkdir tm-dev && cd tm-dev &&       repo init -c -u sso://googleplex-android/platform/manifest -b tm-dev        --use-superproject        --partial-clone --partial-clone-exclude=platform/frameworks/base --clone-filter=blob:limit=10M            && repo sync            -c  -j$(nproc)
```

Once the repo project is fully sync, it is better to build first before bringing changes,
so that in case of a build failure, you know it is just a bad ToT state.
In that case, repo sync again and recompile...

Please use (go/build-fast)[http://go/build-fast] to reduce compile time by 3x.

```
$ source build/envsetup.sh
$ lunch aosp_arm64-eng
$ USE_RBE=true m
```

If all works fine, you should get a build in ~45min (instead of the typical 3 hours)

```
RBE Stats: Downloaded: 15.02 GB, Uploaded: 40.07 MB


#### build completed successfully (47:53 (mm:ss)) ####
```

Now we need to update two repos with the changes necessary for AIDL:

Then we bring the cast-auth Android domain CL with a simple cherry-pick, and keep tracking `goog/tm-dev`:

```
$ cd google/trusty
$ repo start cast-auth
$ cherry pick of the two CL: `libbinder_trusty_paidl` and `cast-auth`
```

Then prepare the device with the Trusty domain,
also making sure the TA to TA unit test works:

Start a `remote_device_proxy` session.

```
$ adb root
$ adb remount
$ adb push cast_auth.app /data/local
$ adb push cast_auth_test.app /data/local
$ adb shell trusty_apploader cast_auth.signed
$ adb shell trusty_apploader cast_auth_test.signed
$ adb shell /vendor/bin/trusty-ut-ctrl -D /dev/trusty-ipc-dev0 com.android.trusty.cast_auth.test
```

Finaly let's start the atest command (which will trigger an incremental build
for the necessary libraries (`libbinder_trusty_paidl.so`, `libcastauth.so`)
as well as the atest `cast_auth_test`

```
$ USE_RBE=true  atest -i -b -t cast_auth_test --disable-teardown --no-bazel-mode
```

The test will fail as the libbinder_trusty_paidl.so is not on device:

```
$ adb root && adb remount
$ adb push out/target/product/xxxx/vendor/lib64/libbinder_trusty_paidl.so /system/lib64/libbinder_trusty_paidl.so
```

Then, the test can be incrementally relaunched with:

```
adb shell /data/local/tests/vendor/cast_auth_test/arm64/cast_auth_test
```

and it should pass!

# Running a NW-TZ IStat callback test

## Dependencies
This CL depends on the following changes to build:

https://android-review.googlesource.com/c/device/generic/trusty/+/2230294
https://android-review.googlesource.com/c/platform/frameworks/native/+/2229484

## Setting up a system to test this CL on qemu
* Checkout aosp trusty, add IStatsSetter TA to it and build it: ./trusty/vendor/google/aosp/scripts/build.py qemu-generic-arm64-test-debug --skip-test
* Checkout aosp_master_with_phones and apply this cl and its dependencies. This example assumes that it has been checked out to ~/aosp_master_with_phones/
* Setup aosp_master_with_phones build for quemu: lunch qemu_trusty_arm64-userdebug
* Build aosp_master_with_phones (RBE helps speeding up builds): USE_RBE=true m
* Start a trusty test using the aosp_master_with_phones image: ./build-root/build-qemu-generic-arm64-test-debug/run --android ~/aosp_master_with_phones/
* Once it finishes booting switch to root user: su root
* Go into vendor/bin: cd vendor/bin
* Run test: ./trusty-istats-test-app
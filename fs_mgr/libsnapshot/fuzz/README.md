# Fuzzer for libsnapshot

## Plugin Design Considerations
The fuzzer plugin for libsnapshot is designed based on the understanding of the
source code and try to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzers.

libsnapshotCow supports the following parameters:
1. Compression Methods (parameter name: "kCompressionMethods")
2. Size (parameter name: "size")
3. Label (parameter name: "label")
4. Version (parameter name: "version")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
|`kCompressionMethods`| 1. `gz` <br> 2. `brotli` <br> 3. `lz4` <br> 4. `zstd` <br> 5. `one` <br>|Value obtained from FuzzedDataProvider|
|`size`| ` Integer in range 0 to 1000` |Value obtained from FuzzedDataProvider|
|`label`| ` Integer in range 0 to 1000` |Value obtained from FuzzedDataProvider|
|`version`| ` Integer in range 0 to 3` |Value obtained from FuzzedDataProvider|

This also ensures that the plugin is always deterministic for any given input.

##### Maximize utilization of input data
The plugin feeds the entire input data to the module.
This ensures that the plugin tolerates any kind of input (empty, huge,
malformed, etc) and doesn't `exit()` on any input and thereby increasing the chance of identifying vulnerabilities.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) libsnapshot_cow_fuzzer
```
#### Steps to run
Create a directory CORPUS_DIR and copy some files to that folder
Push this directory to the device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/libsnapshot_cow_fuzzer/libsnapshot_cow_fuzzer CORPUS_DIR
```
To run on host
```
  $ $ANDROID_HOST_OUT/fuzz/x86_64/libsnapshot_cow_fuzzer/libsnapshot_cow_fuzzer CORPUS_DIR
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz

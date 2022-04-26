# Fuzzers for libinit

## Table of contents
+ [init_parser_fuzzer](#InitParser)
+ [init_property_fuzzer](#InitProperty)
+ [init_ueventHandler_fuzzer](#InitUeventHandler)
+ [init_blockDev_fuzzer](#InitBlockDev)
+ [init_ueventd_fuzzer](#InitUeventD)
+ [init_action_fuzzer](#InitAction)
+ [init_devices_fuzzer](#InitDevices)
+ [init_keychords_fuzzer](#InitKeychords)

# <a name="InitParser"></a> Fuzzer for InitParser

InitParser supports the following parameters:
1. ValidPathNames (parameter name: "kValidPaths")
2. ValidParseInputs (parameter name: "kValidInputs")

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`kValidPaths`| 0.`/system/etc/init/hw/init.rc`,<br/> 1.`/system/etc/init` |Value obtained from FuzzedDataProvider|
|`kValidInputs`| 0.`{"","cpu", "10", "10"}`,<br/> 1.`{"","RLIM_CPU", "10", "10"}`,<br/> 2.`{"","12", "unlimited", "10"}`,<br/> 3.`{"","13", "-1", "10"}`,<br/> 4.`{"","14", "10", "unlimited"}`,<br/> 5.`{"","15", "10", "-1"}` |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) init_parser_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/init_parser_fuzzer/init_parser_fuzzer
```

# <a name="InitProperty"></a> Fuzzer for InitProperty

InitProperty supports the following parameters:
  PropertyType (parameter name: "PropertyType")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
|`PropertyType`| 0.`STRING`,<br/> 1.`BOOL`,<br/> 2.`INT`,<br/> 3.`UINT`,<br/> 4.`DOUBLE`,<br/> 5.`SIZE`,<br/>6.`ENUM`,<br/>7.`RANDOM`|Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) init_property_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/init_property_fuzzer/init_property_fuzzer
```

# <a name="InitUeventHandler"></a> Fuzzer for InitUeventHandler

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

InitUeventHandler supports the following parameters:
1. Major (parameter name: `major`)
2. Minor (parameter name: `minor`)
3. PartitionNum (parameter name: `partition_num`)
4. Uid (parameter name: `uid`)
5. Gid (parameter name: `gid`)
6. Action (parameter name: `action`)
7. Path (parameter name: `path`)
8. Subsystem (parameter name: `subsystem`)
9. PartitionName (parameter name: `partition_name`)
10. DeviceName (parameter name: `device_name`)
11. Modalias (parameter name: `modalias`)
12. DevPath (parameter name: `devPath`)
13. HandlerPath (parameter name: `handlerPath`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `major` | `UINT32_MIN` to `UINT32_MAX` | Value obtained from FuzzedDataProvider|
| `minor` | `UINT32_MIN` to `UINT32_MAX` | Value obtained from FuzzedDataProvider|
| `partition_num ` | `UINT32_MIN` to `UINT32_MAX` | Value obtained from FuzzedDataProvider|
| `uid` | `UINT32_MIN` to `UINT32_MAX` | Value obtained from FuzzedDataProvider|
| `gid` | `UINT32_MIN` to `UINT32_MAX` | Value obtained from FuzzedDataProvider|
| `action` | `String` | Value obtained from FuzzedDataProvider|
| `path` | `String` | Value obtained from FuzzedDataProvider|
| `subsystem` | `String` | Value obtained from FuzzedDataProvider|
| `partition_name` | `String` | Value obtained from FuzzedDataProvider|
| `device_name` | `String` | Value obtained from FuzzedDataProvider|
| `modalias` | `String` | Value obtained from FuzzedDataProvider|
| `devPath` | `String` | Value obtained from FuzzedDataProvider|
| `handlerPath` | `String` | Value obtained from FuzzedDataProvider|

This also ensures that the plugin is always deterministic for any given input.

#### Steps to run
1. Build the fuzzer
```
$ mm -j$(nproc) init_ueventHandler_fuzzer
```
2. Run on device
```
$ adb sync data
$ adb shell /data/fuzz/arm64/init_ueventHandler_fuzzer/init_ueventHandler_fuzzer
```

# <a name="InitBlockDev"></a> Fuzzer for InitBlockDev

InitBlockDev supports the following parameters:
  DeviceSet (parameter name: "devices")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
| `devices` | `String` | Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) init_blockDev_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/init_blockDev_fuzzer/init_blockDev_fuzzer
```

# <a name="InitUeventD"></a> Fuzzer for InitUeventD

InitParser supports the following parameters:
1. ValidPathNames (parameter name: "kValidPaths")
2. ValidFscryptRefPath (parameter name: "kFscryptRefPath")
3. ValidNamespace (parameter name: "kNamespace")
4. FscryptActions (parameter name: "kActions")

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`kValidPaths`| 0.`/apex/`,<br/> 1.`/vendor/` 2.`/system/` |Value obtained from FuzzedDataProvider|
|`kFscryptRefPath`| 0.`ref`,<br/> 1.`/unencrypted/per_boot_ref` |Value obtained from FuzzedDataProvider|
|`kNamespace`| 0.`MountNamespace::NS_BOOTSTRAP`,<br/> 1.`MountNamespace::NS_DEFAULT` |Value obtained from FuzzedDataProvider|
|`kAction`| 0.`FscryptAction::kNone`,<br/> 1.`FscryptAction::kAttempt`,<br/> 2.`FscryptAction::kRequire`,<br/> 3.`FscryptAction::kDeleteIfNecessary` |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) init_ueventd_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/init_ueventd_fuzzer/init_ueventd_fuzzer
```

# <a name="InitAction"></a> Fuzzer for InitAction

InitService supports the following parameters:
  1. PropertyName (parameter name: "name")
  2. ValidActionCommand (parameter name: "validActionCommand")
  3. ValidActionTrigger (parameter name: "validActionTrigger")
  4. FileName (parameter name: "filename")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
|`name`| `String`|Value obtained from FuzzedDataProvider|
|`validActionCommand`| `String` |Value obtained from FuzzedDataProvider|
|`validActionTrigger`| `String`|Value obtained from FuzzedDataProvider|
|`filename`| `String`|Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) init_action_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/init_action_fuzzer/init_action_fuzzer
```

# <a name="InitDevices"></a> Fuzzer for InitDevices

InitDevices supports the following parameters:
  1. PermissionType (parameter name: "kPermissionType")
  2. Action (parameter name: "kAction")
  3. Subsystem (parameter name: "kSubsystem")
  4. DeviceName (parameter name: "kDeviceName")
  5. Attribute (parameter name: "kAttribute")
  6. GroupId (parameter name: "kGroupId")
  7. DevicePaths (parameter name: "kDevicePaths")
  8. ValidPaths (parameter name: "kValidPaths")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
|`kPermissionType`| 0.`0660`,<br/> 1.`0440`,<br/> 2.`0600`,<br/> 3.`0700`,<br/> 4.`0777`,<br/> 5.`0755`|Value obtained from FuzzedDataProvider|
|`kAction`| 0.`add`,<br/> 1.`change`,<br/> 2.`bind`,<br/> 3.`online`,<br/> 4.`remove`|Value obtained from FuzzedDataProvider|
|`kSubsystem`| 0.`block`,<br/> 1.`usb`,<br/> 2.`misc`|Value obtained from FuzzedDataProvider|
|`kDeviceName`| 0.`ashmem`,<br/> 1.`dm-user`|Value obtained from FuzzedDataProvider|
`kAttribute`| 0.`enable`,<br/> 1.`trusty_version`,<br/> 2.`poll_delay`|Value obtained from FuzzedDataProvider|
`kGroupId`| 0.`AID_RADIO`,<br/> 1.`AID_INPUT`,<br/> 2.`AID_LOG`|Value obtained from FuzzedDataProvider|
`kDevicePaths`| 0.`/devices/platform/soc/soc:`,<br/> 1.`/devices/pci0000:00/0000:00:1f.2/`,<br/> 2.`/devices/vbd-1234/`,<br/> 3.`/devices/virtual/block/dm-`|Value obtained from FuzzedDataProvider|
`kValidPaths`| 0.`/sys/bus/platform/devices/soc:*`,<br/> 1.`/sys/devices/virtual/block/dm-*`,<br/> 2.`/sys/bus/i2c/devices/i2c-*`,<br/> 3.`/sys/devices/virtual/input/input*`,<br/> 4.`/sys/class/input/event*`,<br/> 5.`/sys/class/input/input*`|Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) init_devices_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/init_devices_fuzzer/init_devices_fuzzer
```

# <a name="InitKeychords"></a> Fuzzer for InitKeychords

InitKeychords supports the following parameters:
1. Byte (parameter name: "byte")

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`byte`| `8 bit Integer` |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) init_keychords_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/init_keychords_fuzzer/init_keychords_fuzzer
```

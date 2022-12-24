# trusty-busy-ctl

A binary utility allowing to connect to the {trusty_lk_trusty}`app/busytest` TA.

```
$ adb shell /vendor/bin/trusty-busy-ctl -h
```

```
Usage: /vendor/bin/trusty-busy-ctl [options] unittest-app

options:
  -h, --help            prints this message and exit
  -D, --dev name        Trusty device name
  -C, --cfg json-blob   busy-test config as:
                        - a json dictionary of
                            - {cpu:priority}
                            - or {"sleep":duration_sec}
                        - or a json array with a sequence of above commands
```

The config `-C` option allows to pass a json dictionary, where keys represent the cpu id, and values represent the priority for the busy thread pinned to the keyed cpu id.

Once started, `trusty-busy-ctl` will stay connected to busytest, listening
to stdin:

- accepting new json config from stdin
- or quitting upon receiving the character `q` from stdin

Below is an example where:

- the busy thread pinned at cpu 0 is set to priority 24,
- the busy thread pinned at cpu 3 is set to priority 12.

```
$ adb shell /vendor/bin/trusty-busy-ctl -D /dev/trusty-ipc-dev0 -C \''[{"0":24, "3":12},{"sleep":5},{"4":24}]'\'
```

To observe the impact of the Trusty thread priority on the Trusty linux worker thread, use:

```
$ adb shell top
```

set -ex
adb root
adb shell setenforce 0
adb sync
adb shell setprop persist.adb.bench 1
adb shell killall adbd
adb kill-server
sleep 1
bench_adb
adb shell setprop persist.adb.bench 0

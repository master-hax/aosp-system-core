#!/system/bin/sh

netcfg eth0 dhcp
setprop net.dns1 4.2.2.2

# We differ from gphone where display is narrow and tall
#setprop ro.SWAP_PORTRAIT_LANDSCAPE 1
# For pcs with no lid switch default to open
#setprop ro.NOLID_EQUALS_OPEN 1

setprop ro.com.android.dataroaming true

setprop persist.service.adb.enable 1
setprop service.adb.enable 1

echo EeeNoSleep > /sys/android_power/acquire_partial_wake_lock

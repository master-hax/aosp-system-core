#! /bin/bash

if [ X"-s" = X"${1}" -a -n "${2}" ]; then
  export ANDROID_SERIAL="${2}"
  shift 2
fi

adb_sh() {
  adb shell "${@}"
}

adb_reboot() {
  adb reboot remount-test
}

adb_wait() {
  adb wait-for-device
}

die() {
  echo "${@}" >&2
  exit 1
}

check_eq() {
  if [ X"${1}" != X"${2}" ]; then
    die "check_eq \"${1}\" \"${2}\""
  fi
}

# Do something
adb_wait || die "wait for device failed"
adb_sh ls -d /sys/module/overlay || die "overlay module not present"
adb_sh su root ls /sys/module/overlay/parameters/override_creds ||
  die "overlay module can not be used on ANDROID"
adb root &&
  adb_wait &&
  adb_sh setprop persist.adb.remount.overlayfs.maxfree 100 &&
  adb disable-verity ||
    die "setup for overlay"
if adb_sh ls -d /data/overlay >/dev/null; then
  echo "/data/overlay setup, clearing out" >&2
  adb_sh rm -rf /data/overlay ||
    die "/data/overlay removal"
fi
adb_sh ls -d /cache/overlay >/dev/null 2>&1 ||
  adb_sh ls -d /mnt/scratch/overlay >/dev/null 2>&1 ||
  die "overlay directory setup"
adb_reboot &&
  adb_wait &&
  adb_sh df -k | head -1 &&
  adb_sh df -k | grep "^overlay " ||
  die "overlay takeover"
adb root &&
  adb_wait &&
  adb remount &&
  !(adb_sh grep "^overlay " /proc/mounts | grep " overlay ro,") &&
  !(adb_sh grep " rw," /proc/mounts |
  grep -v -e "^\(tmpfs\|overlay\|none\|sysfs\|proc\|selinuxfs\|debugfs\|bpf\|cg2_bpf\|pstore\|tracefs\|adb\|mtp\|ptp\|devpts\|/data/media\) " -e " /\(cache\|mnt/scratch\|mnt/vendor/persist\|metadata\|data\) ") ||
    die "remount"

# Check something
A="Hello World!"
echo ${A} | adb_sh "cat - > /system/hello"
B=`adb_sh cat /system/hello | tr -d "^M"`
check_eq "${A}" "${B}"
adb_reboot &&
  adb_wait &&
  B=`adb_sh cat /system/hello | tr -d "^M"` ||
  die "re-read hello"
check_eq "${A}" "${B}"
adb root &&
  adb_wait &&
  adb remount &&
  adb_sh rm /system/hello ||
  die "cleanup hello"
B=`adb_sh cat /system/hello | tr -d "^M"`
[ -z "${B}" ] || die "cleanup hello"

echo "PASS"

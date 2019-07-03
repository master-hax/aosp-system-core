#!/bin/bash

# source libsnapshot_test.sh && prepare
function prepare() {
    [[ -d $ANDROID_BUILD_TOP ]] || {
        echo "ANDROID_BUILD_TOP?" >&2; return 1;
    }
    [[ -d $ANDROID_PRODUCT_OUT ]] || {
        echo "ANDROID_PRODUCT_OUT?" >&2; return 1;
    }
    [[ -d $ANDROID_BUILD_TOP/external/fio ]] || {
        git clone https://android.googlesource.com/platform/external/fio $ANDROID_BUILD_TOP/external/fio
    }

    git -C $ANDROID_BUILD_TOP/external/fio reset a133df91fa72701e4e448ca1ff81e0c41ed2df8b --hard > /dev/null

    [[ -f $ANDROID_PRODUCT_OUT/system/bin/fio ]] || {
        m fio -j8
    }
    echo $ANDROID_PRODUCT_OUT/system/bin/fio
}

# get_value <key> <<< <dict>
# dict is a multi-line string with format key=value
function get_value() {
    local key=$1; shift;
    cat - | grep -E "^${key}=" | cut -f2 -d'='
}

# https://docs.google.com/document/d/1Dw_mClBSXr9HUKYV0594ykT74_ldWY-Op652rMfRCC8/edit#heading=h.rh6sylud4xh6
function drop_caches() {
    adb shell 'echo 3 > /proc/sys/vm/drop_caches'
}

function pin_cpus() {
    adb shell stop mpdecision 2>/dev/null

    for cpu in $(adb shell 'ls /sys/devices/system/cpu/' | grep -E 'cpu[0-9]'); do
        adb shell "echo 1 > /sys/devices/system/cpu/${cpu}/online"
    done
    for cpu in $(adb shell 'ls /sys/devices/system/cpu/' | grep -E 'cpu[0-9]'); do
        adb shell "echo 'performance' > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
    done
}

function stop_android() {
    adb shell stop
}

function stop_thermal_throttling() {
    adb shell stop perfd vendor.thermal-engine vendor.perfd 2>/dev/null
    adb shell setprop vendor.powerhal.init 0

    # Right now, highest version for power HAL is 1.3.
    for ((ver=3;ver>=0;ver--)); do
        adb shell setprop ctl.restart vendor.power-hal-1-${ver} && break
    done
}

function setup_test() {
    stop_android
    stop_thermal_throttling
    pin_cpus
    drop_caches
}

function extract_bw() {
    local text=$(cat -)
    local line_nums=$(echo "${text}" | grep  -n 'BW=' | cut -f1 -d:)
    [[ -z ${line_nums} ]] && return 1
    for line_num in ${line_nums}; do
        local name=$(echo "${text}" | head -n $((${line_num} - 1)) | tail -n1 | cut -f1 -d:)
        echo ${name}: $(echo "${text}" | head -n ${line_num} | tail -n1 | sed -E 's/^.*BW=(\S*)\s.*$/\1/g')
    done
}

function append_percentage() {
    cat - | {
        while read line; do
            local base=$(echo ${line} | cut -f1 -d' ' | sed -E 's/^([0-9]+)MiB\/s$/\1/g')
            local value=$(echo ${line} | cut -f2 -d' ' | sed -E 's/^([0-9]+)MiB\/s$/\1/g')
            local percentage=$(printf "%.1f" "$(bc -l <<< "(${value} - ${base}) * 100 / ${base}")")
            echo $(echo ${line} | cut -f2 -d' ')"(${percentage}%)"
        done
    }
}

# m libsnapshot_test -j && source libsnapshot_test.sh && run_test
# source libsnapshot_test.sh && run_test
# run_test <device_size> <cow_size>
function run_test() {
    local name=libsnapshot_test
    local test_binary=/data/nativetest64/${name}/${name}
    local fio_binary=/data/local/tmp/fio
    local job_file=/data/local/tmp/myjob.fio

    local paths
    local base
    local cow
    local snapshot
    local merged

    # magic number for device size. A device smaller than this doesn't work
    # (snapshot can't be created.)
    # Need to investigate why.
    local device_size=$1; shift;
    [[ -z ${device_size} ]] && device_size=800m
    local cow_size=$1; shift;
    [[ -z ${cow_size} ]] && cow_size=1g

    [[ -d $ANDROID_BUILD_TOP ]] || {
        echo "ANDROID_BUILD_TOP?" >&2; return 1;
    }
    [[ -d $ANDROID_PRODUCT_OUT ]] || {
        echo "ANDROID_PRODUCT_OUT?" >&2; return 1;
    }

    local dm_linear_report=${ANDROID_PRODUCT_OUT}/fio-dm-linear.txt
    local dm_snapshot_report=${ANDROID_PRODUCT_OUT}/fio-dm-snapshot.txt
    local dm_snapshot_merged_report=${ANDROID_PRODUCT_OUT}/fio-dm-snapshot-merged.txt

    adb root
    adb shell setenforce 0

    adb push $ANDROID_PRODUCT_OUT/${test_binary} ${test_binary}
    adb push $ANDROID_PRODUCT_OUT/system/bin/fio ${fio_binary}
    adb push "$(dirname "$0")"/myjob.fio ${job_file}

    printf "Set up dm-linear...\r"

    paths=$(adb shell ${test_binary} --setup --device-size ${device_size}) || {
        echo "Can't setup" >&2; return 1;
    }
    base=$(echo "${paths}" | get_value base)
    [[ -z ${base} ]] && {
        echo "Can't find path for base device" >&2; return 1;
    }

    setup_test
    printf "Testing dm-linear...\r"
    adb shell ${fio_binary} --filename=${base} ${job_file} > ${dm_linear_report}
    echo ${dm_linear_report}

    printf "Tear down dm-linear...\r"
    adb shell ${test_binary} --teardown

    printf "Set up dm-snapshot...\r"
    paths=$(adb shell ${test_binary} --setup --device-size ${device_size} --cow-size ${cow_size}) || {
        echo "Can't setup" >&2; return 1;
    }
    snapshot=$(echo "${paths}" | get_value snapshot)
    [[ -z ${snapshot} ]] && {
        echo "Can't find path for snapshot device" >&2;
        return 1;
    }

    setup_test
    printf "Testing dm-snapshot...\r"
    adb shell ${fio_binary} --filename=${snapshot} ${job_file} > ${dm_snapshot_report}
    echo ${dm_snapshot_report}

    printf "Merging...\r"
    paths=$(adb shell ${test_binary} --merge) || {
        echo "Can't merge" >&2; return 1;
    }
    merged=$(echo "${paths}" | get_value merged)
    [[ -z ${merged} ]] && {
        echo "Can't find path for merged device" >&2; return 1;
    }

    setup_test
    printf "Testing dm-snapshot-merged...\r"
    adb shell ${fio_binary} --filename=${merged} ${job_file} > ${dm_snapshot_merged_report}
    echo ${dm_snapshot_merged_report}

    printf "Tear down merged dm-snapshot...\r"
    adb shell ${test_binary} --teardown

    printf "%-$(tput cols)s\\r" " "
    echo "*** Summary ***"

    local first_column=$(cat ${dm_linear_report} | extract_bw | cut -f1 -d' ')
    local linear_summary=$(cat ${dm_linear_report} | extract_bw | cut -f2 -d' ')
    local snapshot_summary=$(cat ${dm_snapshot_report} | extract_bw | cut -f2 -d' ')
    local snapshot_merged_summary=$(cat ${dm_snapshot_merged_report} | extract_bw | cut -f2 -d' ')

    snapshot_summary=$(paste <(echo -e "${linear_summary}") <(echo -e "${snapshot_summary}") | append_percentage)
    snapshot_merged_summary=$(paste <(echo -e "${linear_summary}") <(echo -e "${snapshot_merged_summary}") | append_percentage)

    paste <(echo -e "_\n${first_column}") \
          <(echo -e "dm-linear\n${linear_summary}") \
          <(echo -e "dm-snapshot\n${snapshot_summary}") \
          <(echo -e "dm-snapshot-merged\n${snapshot_merged_summary}") \
          | column -t
}

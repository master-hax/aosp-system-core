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

    echo "Set up dm-linear..."

    paths=$(adb shell ${test_binary} --setup --device-size ${device_size}) || {
        echo "Can't setup" >&2; return 1;
    }
    base=$(echo "${paths}" | get_value base)
    [[ -z ${base} ]] && {
        echo "Can't find path for base device" >&2; return 1;
    }

    adb shell ${fio_binary} --filename=${base} ${job_file} > ${dm_linear_report}
    echo ${dm_linear_report}

    echo "Tear down dm-linear..."
    adb shell ${test_binary} --teardown

    echo "Set up dm-snapshot..."
    paths=$(adb shell ${test_binary} --setup --device-size ${device_size} --cow-size ${cow_size}) || {
        echo "Can't setup" >&2; return 1;
    }
    snapshot=$(echo "${paths}" | get_value snapshot)
    [[ -z ${snapshot} ]] && {
        echo "Can't find path for snapshot device" >&2;
        return 1;
    }

    adb shell ${fio_binary} --filename=${snapshot} ${job_file} > ${dm_snapshot_report}
    echo ${dm_snapshot_report}

    echo "Merging..."
    paths=$(adb shell ${test_binary} --merge) || {
        echo "Can't merge" >&2; return 1;
    }
    merged=$(echo "${paths}" | get_value merged)
    [[ -z ${merged} ]] && {
        echo "Can't find path for merged device" >&2; return 1;
    }

    adb shell ${fio_binary} --filename=${merged} ${job_file} > ${dm_snapshot_merged_report}
    echo ${dm_snapshot_merged_report}

    echo "Tear down merged dm-snapshot..."
    adb shell ${test_binary} --teardown

    echo "*** Reports ***"
    echo ${dm_linear_report}
    echo ${dm_snapshot_report}
    echo ${dm_snapshot_merged_report}
}

#!/bin/bash

DEVICE_TMP_DIR=/data/local/tmp
LIBSNAPSHOT_TEST=${DEVICE_TMP_DIR}/libsnapshot_test
FIO=${DEVICE_TMP_DIR}/fio

function host_libsnapshot_test() {
    local TARGET_ARCH=$($ANDROID_BUILD_TOP/build/soong/soong_ui.bash --dumpvar-mode TARGET_ARCH)
    echo ${ANDROID_TARGET_OUT_TESTCASES}/libsnapshot_test/${TARGET_ARCH}/libsnapshot_test
}

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

    if [[ ! -f $ANDROID_PRODUCT_OUT/system/bin/fio ]] || [[ ! -f $(host_libsnapshot_test) ]]; then
        $ANDROID_BUILD_TOP/build/soong/soong_ui.bash --make-mode fio libsnapshot_test -j8
    fi
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
    python -c \
'
import sys,re
job = ""
d=dict()
for line in sys.stdin:
    result = re.search(r"^(\S*):", line)
    if result:
        job = result.group(1)
        continue
    if not job: continue
    result = re.search(r"^\s+(\S*):.*BW=(\S*)", line)
    if result:
        if job not in d: d[job]=dict()
        d[job][result.group(1)] = result.group(2)
for job in d:
    if len(d[job]) == 1:
        print("{}={}".format(job, d[job][next(iter(d[job]))]))
    else:
        for rw in d[job]:
            print("{}-{}={}".format(job, rw[0], d[job][rw]))
' -
}

function print_status() {
    # printf "%-$(tput cols)s\\r" " " 1>&2
    # printf "[$(date '+%H:%M:%S')] $@\r" 1>&2
    echo "[$(date '+%H:%M:%S')] $@" 1>&2
}

# run_test_linear <device_size> <job_file>
function run_test_linear() {
    local device_size=$1; shift
    local job_file=$1; shift

    local paths
    local base

    print_status "Setting up dm-linear..."

    paths=$(adb shell ${LIBSNAPSHOT_TEST} --setup --device-size ${device_size}) || {
        echo "Can't setup" >&2; return 1;
    }
    base=$(echo "${paths}" | get_value base)
    [[ ${base} ]] || {
        echo "Can't find path for base device" >&2; return 1;
    }

    setup_test

    print_status "Testing dm-linear $(basename ${job_file})..."
    adb shell ${FIO} --filename=${base} ${job_file} || return 1

    teardown linear
}


# run_test_linear <device_size> <cow_size> <chunk_size> <job_file>
function run_test_snapshot() {
    local device_size=$1; shift
    local cow_size=$1; shift
    local chunk_size=$1; shift
    local job_file=$1; shift

    local paths
    local snapshot

    print_status "Setting up dm-snapshot..."
    paths=$(adb shell ${LIBSNAPSHOT_TEST} --setup --device-size ${device_size} --cow-size ${cow_size} --chunk-size ${chunk_size}) || {
        echo "Can't setup" >&2;
        return 1;
    }
    snapshot=$(echo "${paths}" | get_value snapshot)
    [[ ${snapshot} ]] || {
        echo "Can't find path for snapshot device" >&2;
        return 1;
    }

    setup_test

    print_status "Testing dm-snapshot $(basename ${job_file})...";
    adb shell SIZE=${SIZE} ${FIO} --filename=${snapshot} ${job_file} || return 1;

    teardown snapshot
}

function teardown() {
    local name=$1
    print_status "Tearing down dm-${name}..."
    adb shell ${LIBSNAPSHOT_TEST} --teardown
}

function unitless() {
    local pretty=$(cat - | sed -E 's/^([0-9.]+)([A-Z]i)?B\/s$/\1 \2/g')
    [[ ${pretty} ]] || return
    local count=$(echo "${pretty}" | cut -f1 -d' ')
    local unit=$(echo "${pretty}" | cut -f2 -d' ')
    for e in "" "Ki" "Mi" "Gi"; do
        [[ ${unit} == ${e} ]] && echo ${count} || {
            count=$(echo "${count} * 1024" | bc -l)
        }
    done
}

# print_summary <files>[ <files> [...]]
function print_summary() {
    [[ "$@" ]] || {
        echo "Missing files." >&2
        return 1
    }
    printf "%-$(tput cols)s\\r" " "
    echo "*** Summary ***"

    local jobs=$(cat "$@" | extract_bw | cut -f1 -d'=' | sort | uniq)
    local cases=$(ls -1 "$@")
    local empty=_
    local ref_summary=

    local table="${empty} $(echo ${jobs})"
    for case in ${cases}; do
        local case_name=$(basename ${case} | sort | sed -E 's/^fio-//g;s/.txt$//g')
        table+="\n${case_name}"
        local case_summary=$(cat ${case} | extract_bw)
        { echo ${case_name} | grep -E 'linear$' > /dev/null; } && ref_summary=$(echo -e "${ref_summary}\n${case_summary}")
        for job in ${jobs}; do
            local entry="$(echo "${case_summary}" | get_value ${job})"
            if [[ ${entry} ]] && ! echo ${case_name} | grep -E 'linear$' > /dev/null; then
                local base=$(echo "${ref_summary}" | get_value ${job})
                local base_count=$(echo ${base} | unitless)
                local value=$(echo ${entry})
                local value_count=$(echo ${value} | unitless)
                [[ ${base} ]] && [[ ${value} ]] && {
                    local percentage=$(printf "%.1f" "$(bc -l <<< "(${value_count} - ${base_count}) * 100 / ${base_count}")")
                    [[ $(echo "(${percentage}) >= 0" | bc -l) == "1" ]] && percentage="+${percentage}"
                    entry+="(${percentage}%)"
                }
            fi
            [[ ${entry} ]] || entry="${empty}"
            table+=" ${entry}"
        done
    done
    echo -e "${table}" | column -t
}

# print_raw_reports <files>[ <files> [...]]
function print_raw_reports() {
    [[ "$@" ]] || {
        echo "Missing files." >&2
        return 1
    }
    for file in $@; do
        printf "%-80s\\n" " " | sed 's/ /#/g'
        echo $(basename ${file})
        printf "%-80s\\n" " " | sed 's/ /#/g'
        cat ${file}
    done
}

function prepare_test() {
    prepare || return 1

    adb root
    adb shell setenforce 0

    adb push $(host_libsnapshot_test) \
             ${ANDROID_PRODUCT_OUT}/system/bin/fio \
             "$(dirname "$0")"/*.fio ${DEVICE_TMP_DIR}/ || return 1
}

# run_test <device_size> <cow_size>
function run_test() {
    # Default device / COW sizes.
    local device_size=$1; shift;
    [[ ${device_size} ]] || device_size=800m
    local cow_size=$1; shift;
    [[ ${cow_size} ]] || cow_size=1g
    local J=${DEVICE_TMP_DIR}
    local R=${ANDROID_PRODUCT_OUT}/fio-

    prepare_test || return 1

    run_test_linear ${device_size} $J/linear.fio \
        > ${R}linear.txt || return 1

    for override_chunk in 8 16 32 64 128; do
        print_status "Testing chunk size ${override_chunk}..."

        run_test_snapshot ${device_size} ${cow_size} ${override_chunk} $J/snapshot-full.fio \
            > ${R}snpst-c$(printf "%03d" ${override_chunk})-fw-r.txt || return 1

        percentages="1 25 50 75"
        [[ ${override_chunk} == "8" ]] && percentages+=" 80 90 95 99 100"

        for i in $percentages; do
            print_status "Testing incremental OTAs that updates ${i}% of partition with chunk size ${override_chunk}..."

            SIZE=${i}% run_test_snapshot ${device_size} ${cow_size} ${override_chunk} $J/snapshot-incremental-w.fio \
                > ${R}snpst-c$(printf "%03d" ${override_chunk})-w-$(printf "%.2f" "$(echo ${i}/100 | bc -l)")-r.txt || return 1
        done
    done

    printf "%-$(tput cols)s\\r" " " 1>&2
    echo "*** Reports ***"
    ls -1 $R*

    echo "*** Joined report ***"
    print_raw_reports $R* > ${ANDROID_PRODUCT_OUT}/joined-report.txt
    echo ${ANDROID_PRODUCT_OUT}/joined-report.txt

    print_summary $R*.txt
}

# memory_test <device_size> <cow_size> <chunk_size>
function memory_test() {
    # Default device / COW sizes.
    local device_size=$1; shift;
    [[ ${device_size} ]] || device_size=800m
    local cow_size=$1; shift;
    [[ ${cow_size} ]] || cow_size=1g
    local chunk_size=$1; shift;
    [[ ${chunk_size} ]] || chunk_size=8
    local J=${DEVICE_TMP_DIR}
    local R=${ANDROID_PRODUCT_OUT}/fio-

    local pic_names=/tmp/pic_names.txt
    rm -rf ${pic_names}
    touch ${pic_names}

    prepare_test || return 1

    nohup "$(dirname "$0")"/mem.py --out ${ANDROID_PRODUCT_OUT} \
        > ${ANDROID_PRODUCT_OUT}/mem_py.out 2> ${ANDROID_PRODUCT_OUT}/mem_py.err &
    mempy_pid=$!

    sleep 2
    run_test_linear ${device_size} \
        $J/linear.fio > /dev/null || return 1
    echo "${R}linear.png" >> ${pic_names}
    sleep 2
    kill -s USR1 ${mempy_pid}

    sleep 2
    run_test_snapshot ${device_size} ${cow_size} ${chunk_size} \
        $J/snapshot-full.fio > /dev/null || return 1
    echo "${R}snpst-c$(printf "%03d" ${chunk_size})-fw-r.png" >> ${pic_names}
    sleep 2
    kill -s USR1 ${mempy_pid}

    for i in 1 25 50 75; do
        print_status "Testing incremental OTAs that updates ${i}% of partition..."
        sleep 2
        SIZE=${i}% run_test_snapshot ${device_size} ${cow_size} ${chunk_size} \
            $J/snapshot-incremental-w.fio > /dev/null || return 1
        echo "${R}snpst-c$(printf "%03d" ${chunk_size})-w-$(printf "%.2f" "$(echo ${i}/100 | bc -l)")-r.png" >> ${pic_names}
        sleep 2
        kill -s USR1 ${mempy_pid}
    done

    sleep 2
    kill -9 ${mempy_pid}

    local command=$(paste <(cat ${ANDROID_PRODUCT_OUT}/mem_py.out) <(cat ${pic_names}) )
    command=$(sed -E 's/^/mv /g;s/$/\;/g' <<< "${command}")

    eval ${command}

    echo "*** Pictures ***"
    cat ${pic_names}
}

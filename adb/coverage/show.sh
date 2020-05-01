<<<<<<< HEAD   (e9c17e Merge "Snap for 6416774 from 67095b28de43087e74b93b8f913338b)
=======
#!/bin/bash

set -euxo pipefail

OUTPUT_DIR=$(realpath $(dirname "$0"))
. "$OUTPUT_DIR"/include.sh

BASE_PATH=/proc/self/cwd/system/core/adb
PATHS=""
if [[ $# == 0 ]]; then
  PATHS=$BASE_PATH
else
  for arg in "$@"; do
    PATHS="$PATHS $BASE_PATH/$arg"
  done
fi

cd $ANDROID_BUILD_TOP
llvm-cov show --instr-profile="$OUTPUT_DIR"/adbd.profdata \
  $ANDROID_PRODUCT_OUT/apex/com.android.adbd/bin/adbd \
  $PATHS \
  $ADB_TEST_BINARIES
>>>>>>> BRANCH (13c657 Merge "init: Add task_profiles init command")

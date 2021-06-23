#!/bin/bash

set +x

DATA_DIR=$(pwd)
TEST_EXE=$ANDROID_HOST_OUT/nativetest64/libutils_test/libutils_test

$TEST_EXE

llvm-profdata merge -sparse default.profraw -o default.profdata

cd $ANDROID_BUILD_TOP
llvm-cov show \
  $TEST_EXE \
  -instr-profile=$DATA_DIR/default.profdata \
  --format=html \
  /proc/self/cwd/system/core/libutils \
  --ignore-filename-regex='.*_test.cpp' \
  --output-dir=/tmp/coverage-html \
  --show-region-summary=false

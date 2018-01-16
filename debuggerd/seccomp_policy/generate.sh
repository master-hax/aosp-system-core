#!/bin/bash

set -ex

cd "$(dirname "$0")"
CPP='cpp -undef -E -P -o - crash_dump.policy.def'
$CPP -D__arm__ > crash_dump.arm.policy
$CPP -D__aarch64__ -D__LP64__ > crash_dump.arm64.policy
$CPP -D__i386__ > crash_dump.x86.policy
$CPP -D__x86_64__ -D__LP64__ > crash_dump.x86_64.policy

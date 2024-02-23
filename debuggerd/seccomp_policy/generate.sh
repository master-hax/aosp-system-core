#!/bin/bash

set -e

cd "$(dirname "$0")"
CPP='cpp -undef -E -P crash_dump.policy.def'
arches=( \
  "arm"      "-D__arm__" \
  "arm64"    "-D__aarch64__ -D__LP64__" \
  "riscv64"  "-D__riscv -D__LP64__" \
  "x86"      "-D__i386__" \
  "x86_64"   "-D__x86_64__ -D__LP64__" \
)

# Normal pass
for ((i = 0; i < ${#arches[@]}; i = i + 2)); do
  arch=${arches[$i]}
  arch_defines=${arches[$((i+1))]}
  echo "Generating normal policy for ${arch}"
  ${CPP} ${arch_defines} -o crash_dump.${arch}.policy
done

# Generate version without mmap/mprotect rules
# This is needed for swcodec to be able to include the policy file since that
# process requires a more permissive version of these syscalls.
for ((i = 0; i < ${#arches[@]}; i = i + 2)); do
  arch=${arches[$i]}
  arch_defines=${arches[$((i+1))]}
  echo "Generating no mmap/mprotect policy for ${arch}"
  ${CPP} ${arch_defines} -DNO_MMAP_MPROTECT_RULES -o crash_dump.no_mmap_mprotect.${arch}.policy
done

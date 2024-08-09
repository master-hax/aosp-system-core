#pragma once

// Prints out compile-time constant values known by Clang for an arm32 compile target.
void printArm32TargetFeatures();

// Prints out compile-time constant values known by Clang for an aarch64 compile target.
void printAarch64TargetFeatures();

// Prints out compile-time constant values known by Clang for an x86 (and x86-64) compile target.
void printX86TargetFeatures();

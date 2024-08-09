/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

// Prints out compile-time constant values known by Clang for an arm32 compile target.
void printArm32TargetFeatures();

// Prints out compile-time constant values known by Clang for an aarch64 compile target.
void printAarch64TargetFeatures();

// Prints out compile-time constant values known by Clang for an x86 (and x86-64) compile target.
void printX86TargetFeatures();

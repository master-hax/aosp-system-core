/*
 * Copyright (C) 2019 The Android Open Source Project
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

// Resources in /product/etc/res overrides resources in /res.
// If the device is using the Generic System Image (GSI), resources may exist in
// both paths.
static constexpr const char* animation_desc_path = "/res/values/charger/animation.txt";
static constexpr const char* product_animation_desc_path =
        "/product/etc/res/values/charger/animation.txt";
static constexpr const char* product_animation_root = "/product/etc/res/images/";

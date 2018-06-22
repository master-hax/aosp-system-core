/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

#include <unistd.h>

#include <android-base/properties.h>
#include <android/log.h>
#include <cutils/misc.h>

#include "TypedSystemProperty.h"

namespace android::TypedSystemProperty {

static constexpr const char* kPrefixWriteonce = "ro.";

template <typename T>
bool SystemPropertyBase<T>::WorldReadonly(const SystemPropertyBase<T>& /* prop */, bool write) {
    return !write;
};

template <typename T>
bool SystemPropertyBase<T>::PlatformWritable(const SystemPropertyBase<T>& /* prop */,
                                             bool /* write */) {
    int uid = getuid();
    return uid >= 0 && uid < FIRST_APPLICATION_UID;
};

template <typename T>
bool SystemPropertyBase<T>::PlatformReadonly(const SystemPropertyBase<T>& /* prop */, bool write) {
    int uid = getuid();
    return uid >= 0 && uid < FIRST_APPLICATION_UID && !write;
};

template <typename T>
bool SystemPropertyBase<T>::AppReadonly(const SystemPropertyBase<T>& /* prop */, bool write) {
    int uid = getuid();
    return uid >= FIRST_APPLICATION_UID && uid < LAST_APPLICATION_UID && !write;
};

template <typename T>
struct SystemPropertyBase<T>::SystemPropertyData {
    const std::string namespace_;
    const std::string full_name_;
    const bool writeonce_;
    const std::optional<T> default_value_;
    const Accessor accessor_;

    const bool is_platform_prop_;
};

template <typename T>
SystemPropertyBase<T>::SystemPropertyBase(const std::string& name, const std::string& namespace__,
                                          bool writeonce, std::optional<T> default_value,
                                          Accessor accessor, bool is_platform_prop)
    : data_(new SystemPropertyData{
              namespace__, (writeonce ? "" : kPrefixWriteonce) + namespace__ + "." + name,
              writeonce, std::move(default_value), std::move(accessor), is_platform_prop}) {
    CheckNamespace();
}

template <typename T>
SystemPropertyBase<T>::~SystemPropertyBase() {
    delete data_;
}

template <typename T>
void SystemPropertyBase<T>::CheckNamespace() {
    bool is_vendor_or_odm_namespace =
            (data_->namespace_ == kNamespaceVendor || data_->namespace_ == kNamespaceOdm);

    if (data_->is_platform_prop_) {
        if (is_vendor_or_odm_namespace) {
            // TODO: LOG_FATAL
            // "Namespace of a platform defined system property "
            // + full_name_ + " must not be " + namespace_);
        }
    } else {
        if (!is_vendor_or_odm_namespace) {
            // TODO: LOG_FATAL
            // "Namespace of " + full_name_ + " is " + namespace_ + ". "
            // "Should be one of " + kNamespaceVendor + " or " +
            // kNamespaceOdm ".";
        }
    }
}

template <typename T>
bool SystemPropertyBase<T>::IsWriteOnce() const {
    return data_->writeonce_;
}

template <typename T>
std::string SystemPropertyBase<T>::FullName() const {
    return data_->full_name_;
}

template <typename T>
std::optional<T> SystemPropertyBase<T>::Get() const {
    if (data_->accessor_(*this, false)) {
        // TODO: LOG
        return std::nullopt;
    }
    std::string value = android::base::GetProperty(FullName(), "");

    if (value.empty()) return data_->default_value_;

    std::optional<T> ret = ParseValue(value);
    if (ret.has_value() == false) {
        // TODO: LOG failed to parse value
        return data_->default_value_;
    }

    return ret;
}

template <typename T>
void SystemPropertyBase<T>::Set(const T& value) {
    if (data_->accessor_(*this, true)) {
        // TODO: LOG
        return;
    }
    if (data_->writeonce_ && Get().has_value()) {
        // TODO: LOG (and throw?)
    }
    android::base::SetProperty(FullName(), FormatValue(value));
}

std::optional<double> DoubleSystemProperty::ParseValue(const std::string& value) const {
    double ret;
    return std::sscanf(value.c_str(), "%lf", &ret) == 1 ? std::make_optional(ret) : std::nullopt;
}

std::string DoubleSystemProperty::FormatValue(const double& value) const {
    // TODO: only 6 digits will be returned, might need more precision
    return std::to_string(value);
}

std::optional<float> FloatSystemProperty::ParseValue(const std::string& value) const {
    float ret;
    return std::sscanf(value.c_str(), "%f", &ret) == 1 ? std::make_optional(ret) : std::nullopt;
}

std::string FloatSystemProperty::FormatValue(const float& value) const {
    // TODO: only 6 digits will be returned, might need more precision
    return std::to_string(value);
}

std::optional<std::int32_t> IntegerSystemProperty::ParseValue(const std::string& value) const {
    std::int32_t ret;
    return std::sscanf(value.c_str(), "%" SCNd32, &ret) == 1 ? std::make_optional(ret)
                                                             : std::nullopt;
}

std::string IntegerSystemProperty::FormatValue(const std::int32_t& value) const {
    return std::to_string(value);
}

std::optional<std::int64_t> LongSystemProperty::ParseValue(const std::string& value) const {
    std::int64_t ret;
    return std::sscanf(value.c_str(), "%" SCNd64, &ret) == 1 ? std::make_optional(ret)
                                                             : std::nullopt;
}

std::string LongSystemProperty::FormatValue(const std::int64_t& value) const {
    return std::to_string(value);
}

std::optional<std::string> StringSystemProperty::ParseValue(const std::string& value) const {
    return std::make_optional(value);
}
std::string StringSystemProperty::FormatValue(const std::string& value) const {
    return value;
}

std::optional<bool> BooleanSystemProperty::ParseValue(const std::string& value) const {
    static constexpr const char* kYes[] = {"1", "on", "true", "y", "yes"};
    static constexpr const char* kNo[] = {"0", "off", "false", "n", "no"};

    for (const char* yes : kYes) {
        if (strcasecmp(yes, value.c_str()) == 0) return std::make_optional(true);
    }

    for (const char* no : kNo) {
        if (strcasecmp(no, value.c_str()) == 0) return std::make_optional(false);
    }

    return std::nullopt;
}

std::string BooleanSystemProperty::FormatValue(const bool& value) const {
    return value ? "true" : "false";
}

std::optional<std::int32_t> EnumSystemProperty::ParseValue(const std::string& value) const {
    auto itr = values_.find(value);
    return itr != values_.end() ? std::make_optional(itr->second) : std::nullopt;
}

std::string EnumSystemProperty::FormatValue(const std::int32_t& value) const {
    auto itr = names_.find(value);
    return itr != names_.end() ? itr->second : "";
}

EnumSystemProperty::EnumSystemProperty(const std::string& name, const std::string& namespace__,
                                       bool writeonce, std::optional<std::int32_t> default_value,
                                       Accessor accessor, bool is_platform_prop,
                                       std::unordered_map<std::string, std::int32_t> enum_values)
    : SystemPropertyBase<std::int32_t>(name, namespace__, writeonce, std::move(default_value),
                                       std::move(accessor), is_platform_prop),
      values_(std::move(enum_values)) {
    for (const auto& value : values_) {
        names_.emplace(value.second, value.first);
    }
}

template class SystemPropertyBase<bool>;
template class SystemPropertyBase<std::int32_t>;
template class SystemPropertyBase<std::int64_t>;
template class SystemPropertyBase<double>;
template class SystemPropertyBase<float>;
template class SystemPropertyBase<std::string>;

}  // namespace android::TypedSystemProperty

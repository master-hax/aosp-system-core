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

#include "include/sysprop/sysprop.h"

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "libsysprop"
#endif

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
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/misc.h>
#include <log/log.h>

namespace android::sysprop {

// Internal linkage
namespace {

constexpr const char* kNamespacePlatform = "";
constexpr const char* kNamespaceVendor = "vendor.";
constexpr const char* kNamespaceOdm = "odm.";
constexpr const char* kPrefixWriteonce = "ro.";

std::string GenerateFullName(const std::string& name, PropertyNamespace prop_namespace,
                             bool writeonce) {
    std::string prefix;
    if (writeonce) prefix = kPrefixWriteonce;

    switch (prop_namespace) {
        case PropertyNamespace::Platform:
            prefix += kNamespacePlatform;
            break;
        case PropertyNamespace::Vendor:
            prefix += kNamespaceVendor;
            break;
        case PropertyNamespace::Odm:
            prefix += kNamespaceOdm;
            break;
        default:
            break;
    }

    prefix += name;
    return prefix;
}

class EnumProperty::EnumPropertyImpl {
  public:
    explicit EnumPropertyImpl(EnumProperty& prop,
                              std::unordered_map<std::string, std::int32_t> enum_values)
        : prop_(prop), values_(std::move(enum_values)) {
        for (const auto& value : values_) {
            names_.emplace(value.second, value.first);
        }
    }

    std::optional<std::int32_t> ParseValue(const std::string& value) const {
        auto itr = values_.find(value);
        return itr != values_.end() ? std::make_optional(itr->second) : std::nullopt;
    }

    std::string FormatValue(std::int32_t value) const {
        auto itr = names_.find(value);
        if (itr != names_.end()) return itr->second;

        // TODO: LOG_ALWAYS_FATAL?
        ALOGE("invalid enum value %d for property %s", value, prop_.FullName().c_str());

        return "";
    }

  private:
    EnumPropertyImpl& operator=(const EnumPropertyImpl&) = delete;

    EnumProperty& prop_;
    std::unordered_map<std::string, std::int32_t> values_;
    std::unordered_map<std::int32_t, std::string> names_;
};

}  // namespace

bool WorldReadonly(bool write) {
    return !write;
};

bool PlatformWritable([[maybe_unused]] bool write) {
    int uid = getuid();
    return uid >= 0 && uid < FIRST_APPLICATION_UID;
};

bool PlatformReadonly(bool write) {
    int uid = getuid();
    return uid >= 0 && uid < FIRST_APPLICATION_UID && !write;
};

bool AppReadonly(bool write) {
    int uid = getuid();
    return uid >= FIRST_APPLICATION_UID && uid < LAST_APPLICATION_UID && !write;
};

template <typename T>
struct SystemPropertyBase<T>::SystemPropertyData {
    const PropertyNamespace namespace_;
    const std::string full_name_;
    const bool writeonce_;
    const std::optional<T> default_value_;
    const Accessor accessor_;
    const bool is_platform_prop_;

    SystemPropertyData(PropertyNamespace namespace__, std::string full_name, bool writeonce,
                       std::optional<T> default_value, Accessor accessor, bool is_platform_prop)
        : namespace_(namespace__),
          full_name_(std::move(full_name)),
          writeonce_(writeonce),
          default_value_(std::move(default_value)),
          accessor_(std::move(accessor)),
          is_platform_prop_(is_platform_prop) {}
};

template <typename T>
SystemPropertyBase<T>::SystemPropertyBase(const std::string& name, PropertyNamespace prop_namespace,
                                          bool writeonce, std::optional<T> default_value,
                                          Accessor accessor, bool is_platform_prop)
    : data_(std::make_unique<SystemPropertyData>(
              prop_namespace, GenerateFullName(name, prop_namespace, writeonce), writeonce,
              std::move(default_value), std::move(accessor), is_platform_prop)) {
    CheckNamespace();
}

template <typename T>
SystemPropertyBase<T>::~SystemPropertyBase() = default;

template <typename T>
void SystemPropertyBase<T>::CheckNamespace() {
    bool is_vendor_or_odm_namespace = data_->prop_namespace_ == PropertyNamespace::Vendor ||
                                      data_->prop_namespace_ == PropertyNamespace::Odm;

    if (data_->is_platform_prop_) {
        if (is_vendor_or_odm_namespace) {
            LOG_ALWAYS_FATAL(
                    "Namespace of a platform defined system property %s must not be %s or %s\n",
                    name.c_str(), kNamespaceVendor, kNamespaceOdm);
        }
    } else {
        if (!is_vendor_or_odm_namespace) {
            LOG_ALWAYS_FATAL("Namespace of %s should be one of %s or %s\n", name.c_str(),
                             kNamespaceVendor, kNamespaceOdm);
        }
    }
}

template <typename T>
bool SystemPropertyBase<T>::IsWriteOnce() const {
    return data_->writeonce_;
}

template <typename T>
const std::string& SystemPropertyBase<T>::FullName() const {
    return data_->full_name_;
}

template <typename T>
std::optional<T> SystemPropertyBase<T>::Get() const {
    if (data_->accessor_(false)) {
        ALOGE("This process does not have read access to %s", data_->full_name_.c_str());
        return std::nullopt;
    }
    std::string value = android::base::GetProperty(data_->full_name_, "");

    if (value.empty()) return data_->default_value_;

    std::optional<T> ret = ParseValue(value);
    if (ret.has_value() == false) {
        ALOGE("Failed to parse the value of %s (%s)", data_->full_name_.c_str(), value.c_str());
        return data_->default_value_;
    }

    return ret;
}

template <typename T>
void SystemPropertyBase<T>::Set(const T& value) {
    if (data_->accessor_(true)) {
        ALOGE("This process does not have write access to %s", data_->full_name_.c_str());
        return;
    }
    std::optional<T> res = Get();
    if (data_->writeonce_ && res.has_value()) {
        ALOGE("%s can't be overwritten. Current value: %s", data_->full_name_.c_str(),
              FormatValue(*res).c_str());
        return;
    }
    android::base::SetProperty(data_->full_name_, FormatValue(value));
}

DoubleProperty::DoubleProperty(const std::string& name, PropertyNamespace prop_namespace,
                               bool writeonce, std::optional<double> default_value,
                               Accessor accessor, bool is_platform_prop)
    : SystemPropertyBase<double>(name, prop_namespace, writeonce, std::move(default_value),
                                 std::move(accessor), is_platform_prop) {}

DoubleProperty::DoubleProperty(const std::string& name, PropertyNamespace prop_namespace,
                               bool writeonce, std::optional<double> default_value,
                               Accessor accessor)
    : DoubleProperty(name, prop_namespace, writeonce, std::move(default_value), std::move(accessor),
                     false) {}

DoubleProperty::~DoubleProperty() = default;

std::optional<double> DoubleProperty::ParseValue(const std::string& value) const {
    double ret;
    return std::sscanf(value.c_str(), "%lf", &ret) == 1 ? std::make_optional(ret) : std::nullopt;
}

std::string DoubleProperty::FormatValue(const double& value) const {
    return android::base::StringPrintf("%.*g", std::numeric_limits<double>::max_digits10, value);
}

FloatProperty::FloatProperty(const std::string& name, PropertyNamespace prop_namespace,
                             bool writeonce, std::optional<float> default_value, Accessor accessor,
                             bool is_platform_prop)
    : SystemPropertyBase<float>(name, prop_namespace, writeonce, std::move(default_value),
                                std::move(accessor), is_platform_prop) {}

FloatProperty::FloatProperty(const std::string& name, PropertyNamespace prop_namespace,
                             bool writeonce, std::optional<float> default_value, Accessor accessor)
    : FloatProperty(name, prop_namespace, writeonce, std::move(default_value), std::move(accessor),
                    false) {}

FloatProperty::~FloatProperty() = default;

std::optional<float> FloatProperty::ParseValue(const std::string& value) const {
    float ret;
    return std::sscanf(value.c_str(), "%f", &ret) == 1 ? std::make_optional(ret) : std::nullopt;
}

std::string FloatProperty::FormatValue(const float& value) const {
    return android::base::StringPrintf("%.*g", std::numeric_limits<float>::max_digits10, value);
}

IntegerProperty::IntegerProperty(const std::string& name, PropertyNamespace prop_namespace,
                                 bool writeonce, std::optional<std::int32_t> default_value,
                                 Accessor accessor, bool is_platform_prop)
    : SystemPropertyBase<std::int32_t>(name, prop_namespace, writeonce, std::move(default_value),
                                       std::move(accessor), is_platform_prop) {}

IntegerProperty::IntegerProperty(const std::string& name, PropertyNamespace prop_namespace,
                                 bool writeonce, std::optional<std::int32_t> default_value,
                                 Accessor accessor)
    : IntegerProperty(name, prop_namespace, writeonce, std::move(default_value),
                      std::move(accessor), false) {}

IntegerProperty::~IntegerProperty() = default;

std::optional<std::int32_t> IntegerProperty::ParseValue(const std::string& value) const {
    std::int32_t ret;
    return std::sscanf(value.c_str(), "%" SCNd32, &ret) == 1 ? std::make_optional(ret)
                                                             : std::nullopt;
}

std::string IntegerProperty::FormatValue(const std::int32_t& value) const {
    return std::to_string(value);
}

LongProperty::LongProperty(const std::string& name, PropertyNamespace prop_namespace,
                           bool writeonce, std::optional<std::int64_t> default_value,
                           Accessor accessor, bool is_platform_prop)
    : SystemPropertyBase<std::int64_t>(name, prop_namespace, writeonce, std::move(default_value),
                                       std::move(accessor), is_platform_prop) {}

LongProperty::LongProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                           std::optional<std::int64_t> default_value, Accessor accessor)
    : LongProperty(name, prop_namespace, writeonce, std::move(default_value), std::move(accessor),
                   false) {}

LongProperty::~LongProperty() = default;

std::optional<std::int64_t> LongProperty::ParseValue(const std::string& value) const {
    std::int64_t ret;
    return std::sscanf(value.c_str(), "%" SCNd64, &ret) == 1 ? std::make_optional(ret)
                                                             : std::nullopt;
}

std::string LongProperty::FormatValue(const std::int64_t& value) const {
    return std::to_string(value);
}

StringProperty::StringProperty(const std::string& name, PropertyNamespace prop_namespace,
                               bool writeonce, std::optional<std::string> default_value,
                               Accessor accessor, bool is_platform_prop)
    : SystemPropertyBase<std::string>(name, prop_namespace, writeonce, std::move(default_value),
                                      std::move(accessor), is_platform_prop) {}

StringProperty::StringProperty(const std::string& name, PropertyNamespace prop_namespace,
                               bool writeonce, std::optional<std::string> default_value,
                               Accessor accessor)
    : StringProperty(name, prop_namespace, writeonce, std::move(default_value), std::move(accessor),
                     false) {}

StringProperty::~StringProperty() = default;

std::optional<std::string> StringProperty::ParseValue(const std::string& value) const {
    return std::make_optional(value);
}

std::string StringProperty::FormatValue(const std::string& value) const {
    return value;
}

BooleanProperty::BooleanProperty(const std::string& name, PropertyNamespace prop_namespace,
                                 bool writeonce, std::optional<bool> default_value,
                                 Accessor accessor, bool is_platform_prop)
    : SystemPropertyBase<bool>(name, prop_namespace, writeonce, std::move(default_value),
                               std::move(accessor), is_platform_prop) {}

BooleanProperty::BooleanProperty(const std::string& name, PropertyNamespace prop_namespace,
                                 bool writeonce, std::optional<bool> default_value,
                                 Accessor accessor)
    : BooleanProperty(name, prop_namespace, writeonce, std::move(default_value),
                      std::move(accessor), false) {}

BooleanProperty::~BooleanProperty() = default;

std::optional<bool> BooleanProperty::ParseValue(const std::string& value) const {
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

std::string BooleanProperty::FormatValue(const bool& value) const {
    return value ? "true" : "false";
}

EnumProperty::EnumProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                           std::optional<std::int32_t> default_value, Accessor accessor,
                           std::unordered_map<std::string, std::int32_t> enum_values,
                           bool is_platform_prop)
    : SystemPropertyBase<std::int32_t>(name, prop_namespace, writeonce, std::move(default_value),
                                       std::move(accessor), is_platform_prop),
      impl_(std::make_unique<EnumPropertyImpl>(*this, std::move(enum_values))) {}

EnumProperty::EnumProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                           std::optional<std::int32_t> default_value, Accessor accessor,
                           std::unordered_map<std::string, std::int32_t> enum_values)
    : EnumProperty(name, prop_namespace, writeonce, std::move(default_value), std::move(accessor),
                   std::move(enum_values), false) {}

EnumProperty::~EnumProperty() = default;

std::optional<std::int32_t> EnumProperty::ParseValue(const std::string& value) const {
    return impl_->ParseValue(value);
}

std::string EnumProperty::FormatValue(const std::int32_t& value) const {
    return impl_->FormatValue(value);
}

template class SystemPropertyBase<bool>;
template class SystemPropertyBase<std::int32_t>;
template class SystemPropertyBase<std::int64_t>;
template class SystemPropertyBase<double>;
template class SystemPropertyBase<float>;
template class SystemPropertyBase<std::string>;

}  // namespace android::sysprop

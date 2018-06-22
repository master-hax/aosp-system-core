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

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "libsysprop"

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

#include "include/sysprop.h"

namespace android::sysprop {

static constexpr const char* kNamespacePlatform = "";
static constexpr const char* kNamespaceVendor = "vendor.";
static constexpr const char* kNamespaceOdm = "odm.";
static constexpr const char* kPrefixWriteonce = "ro.";

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

static std::string GenerateFullName(const std::string& name, PropertyNamespace prop_namespace,
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

    return prefix + name;
}

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
    // It's not enough to just look at data_->namespace_ as platform properties
    // has no unique prefix (kNamespacePlatform == "")

    const std::string& name = data_->full_name_;

    bool is_vendor_or_odm_namespace = android::base::StartsWith(name, kNamespaceVendor) ||
                                      android::base::StartsWith(name, kNamespaceOdm);

    if (data_->is_platform_prop_) {
        if (is_vendor_or_odm_namespace) {
            LOG_ALWAYS_FATAL("Namespace of a platform defined system property %s must not be %s\n",
                             name.c_str(), name.substr(0, name.find_first_of('.')).c_str());
        }
    } else {
        if (!is_vendor_or_odm_namespace) {
            LOG_ALWAYS_FATAL("Namespace of %s Should be one of %s or %s\n", name.c_str(),
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

DoubleSystemProperty::DoubleSystemProperty(const std::string& name, PropertyNamespace prop_namespace,
                                           bool writeonce, std::optional<double> default_value,
                                           Accessor accessor, bool is_platform_prop)
    : SystemPropertyBase<double>(name, prop_namespace, writeonce, std::move(default_value),
                                 std::move(accessor), is_platform_prop) {}

DoubleSystemProperty::DoubleSystemProperty(const std::string& name,
                                           PropertyNamespace prop_namespace, bool writeonce,
                                           std::optional<double> default_value, Accessor accessor)
    : DoubleSystemProperty(name, prop_namespace, writeonce, std::move(default_value),
                           std::move(accessor), false) {}

DoubleSystemProperty::~DoubleSystemProperty() = default;

std::optional<double> DoubleSystemProperty::ParseValue(const std::string& value) const {
    double ret;
    return std::sscanf(value.c_str(), "%lf", &ret) == 1 ? std::make_optional(ret) : std::nullopt;
}

std::string DoubleSystemProperty::FormatValue(const double& value) const {
    return android::base::StringPrintf("%.*g", std::numeric_limits<double>::max_digits10, value);
}

FloatSystemProperty::FloatSystemProperty(const std::string& name, PropertyNamespace prop_namespace,
                                         bool writeonce, std::optional<float> default_value,
                                         Accessor accessor, bool is_platform_prop)
    : SystemPropertyBase<float>(name, prop_namespace, writeonce, std::move(default_value),
                                std::move(accessor), is_platform_prop) {}

FloatSystemProperty::FloatSystemProperty(const std::string& name, PropertyNamespace prop_namespace,
                                         bool writeonce, std::optional<float> default_value,
                                         Accessor accessor)
    : FloatSystemProperty(name, prop_namespace, writeonce, std::move(default_value),
                          std::move(accessor), false) {}

FloatSystemProperty::~FloatSystemProperty() = default;

std::optional<float> FloatSystemProperty::ParseValue(const std::string& value) const {
    float ret;
    return std::sscanf(value.c_str(), "%f", &ret) == 1 ? std::make_optional(ret) : std::nullopt;
}

std::string FloatSystemProperty::FormatValue(const float& value) const {
    return android::base::StringPrintf("%.*g", std::numeric_limits<float>::max_digits10, value);
}

IntegerSystemProperty::IntegerSystemProperty(const std::string& name,
                                             PropertyNamespace prop_namespace, bool writeonce,
                                             std::optional<std::int32_t> default_value,
                                             Accessor accessor, bool is_platform_prop)
    : SystemPropertyBase<std::int32_t>(name, prop_namespace, writeonce, std::move(default_value),
                                       std::move(accessor), is_platform_prop) {}

IntegerSystemProperty::IntegerSystemProperty(const std::string& name,
                                             PropertyNamespace prop_namespace, bool writeonce,
                                             std::optional<std::int32_t> default_value,
                                             Accessor accessor)
    : IntegerSystemProperty(name, prop_namespace, writeonce, std::move(default_value),
                            std::move(accessor), false) {}

IntegerSystemProperty::~IntegerSystemProperty() = default;

std::optional<std::int32_t> IntegerSystemProperty::ParseValue(const std::string& value) const {
    std::int32_t ret;
    return std::sscanf(value.c_str(), "%" SCNd32, &ret) == 1 ? std::make_optional(ret)
                                                             : std::nullopt;
}

std::string IntegerSystemProperty::FormatValue(const std::int32_t& value) const {
    return std::to_string(value);
}

LongSystemProperty::LongSystemProperty(const std::string& name, PropertyNamespace prop_namespace,
                                       bool writeonce, std::optional<std::int64_t> default_value,
                                       Accessor accessor, bool is_platform_prop)
    : SystemPropertyBase<std::int64_t>(name, prop_namespace, writeonce, std::move(default_value),
                                       std::move(accessor), is_platform_prop) {}

LongSystemProperty::LongSystemProperty(const std::string& name, PropertyNamespace prop_namespace,
                                       bool writeonce, std::optional<std::int64_t> default_value,
                                       Accessor accessor)
    : LongSystemProperty(name, prop_namespace, writeonce, std::move(default_value),
                         std::move(accessor), false) {}

LongSystemProperty::~LongSystemProperty() = default;

std::optional<std::int64_t> LongSystemProperty::ParseValue(const std::string& value) const {
    std::int64_t ret;
    return std::sscanf(value.c_str(), "%" SCNd64, &ret) == 1 ? std::make_optional(ret)
                                                             : std::nullopt;
}

std::string LongSystemProperty::FormatValue(const std::int64_t& value) const {
    return std::to_string(value);
}

StringSystemProperty::StringSystemProperty(const std::string& name, PropertyNamespace prop_namespace,
                                           bool writeonce, std::optional<std::string> default_value,
                                           Accessor accessor, bool is_platform_prop)
    : SystemPropertyBase<std::string>(name, prop_namespace, writeonce, std::move(default_value),
                                      std::move(accessor), is_platform_prop) {}

StringSystemProperty::StringSystemProperty(const std::string& name, PropertyNamespace prop_namespace,
                                           bool writeonce, std::optional<std::string> default_value,
                                           Accessor accessor)
    : StringSystemProperty(name, prop_namespace, writeonce, std::move(default_value),
                           std::move(accessor), false) {}

StringSystemProperty::~StringSystemProperty() = default;

std::optional<std::string> StringSystemProperty::ParseValue(const std::string& value) const {
    return std::make_optional(value);
}

std::string StringSystemProperty::FormatValue(const std::string& value) const {
    return value;
}

BooleanSystemProperty::BooleanSystemProperty(const std::string& name,
                                             PropertyNamespace prop_namespace, bool writeonce,
                                             std::optional<bool> default_value, Accessor accessor,
                                             bool is_platform_prop)
    : SystemPropertyBase<bool>(name, prop_namespace, writeonce, std::move(default_value),
                               std::move(accessor), is_platform_prop) {}

BooleanSystemProperty::BooleanSystemProperty(const std::string& name,
                                             PropertyNamespace prop_namespace, bool writeonce,
                                             std::optional<bool> default_value, Accessor accessor)
    : BooleanSystemProperty(name, prop_namespace, writeonce, std::move(default_value),
                            std::move(accessor), false) {}

BooleanSystemProperty::~BooleanSystemProperty() = default;

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

class EnumSystemProperty::EnumSystemPropertyImpl {
  public:
    explicit EnumSystemPropertyImpl(EnumSystemProperty& prop,
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
    EnumSystemPropertyImpl& operator=(const EnumSystemPropertyImpl&) = delete;

    EnumSystemProperty& prop_;
    std::unordered_map<std::string, std::int32_t> values_;
    std::unordered_map<std::int32_t, std::string> names_;
};

EnumSystemProperty::EnumSystemProperty(const std::string& name, PropertyNamespace prop_namespace,
                                       bool writeonce, std::optional<std::int32_t> default_value,
                                       Accessor accessor,
                                       std::unordered_map<std::string, std::int32_t> enum_values,
                                       bool is_platform_prop)
    : SystemPropertyBase<std::int32_t>(name, prop_namespace, writeonce, std::move(default_value),
                                       std::move(accessor), is_platform_prop),
      impl_(std::make_unique<EnumSystemPropertyImpl>(*this, std::move(enum_values))) {}

EnumSystemProperty::EnumSystemProperty(const std::string& name, PropertyNamespace prop_namespace,
                                       bool writeonce, std::optional<std::int32_t> default_value,
                                       Accessor accessor,
                                       std::unordered_map<std::string, std::int32_t> enum_values)
    : EnumSystemProperty(name, prop_namespace, writeonce, std::move(default_value),
                         std::move(accessor), std::move(enum_values), false) {}

EnumSystemProperty::~EnumSystemProperty() = default;

std::optional<std::int32_t> EnumSystemProperty::ParseValue(const std::string& value) const {
    return impl_->ParseValue(value);
}

std::string EnumSystemProperty::FormatValue(const std::int32_t& value) const {
    return impl_->FormatValue(value);
}

template class SystemPropertyBase<bool>;
template class SystemPropertyBase<std::int32_t>;
template class SystemPropertyBase<std::int64_t>;
template class SystemPropertyBase<double>;
template class SystemPropertyBase<float>;
template class SystemPropertyBase<std::string>;

}  // namespace android::sysprop

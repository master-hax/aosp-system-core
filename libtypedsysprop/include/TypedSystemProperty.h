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

#ifndef SYSTEM_CORE_LIBTYPEDSYSPROP_TYPEDSYSTEMPROPERTY_H_
#define SYSTEM_CORE_LIBTYPEDSYSPROP_TYPEDSYSTEMPROPERTY_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

namespace android::typedsystemproperty {

class PlatformProperties;

enum class PropertyNamespace { Platform, Vendor, Odm };

template <typename T>
class SystemPropertyBase {
  public:
    using Accessor = std::function<bool(const SystemPropertyBase<T>& prop, bool write)>;

    // Predefined accessors
    static bool WorldReadonly(const SystemPropertyBase<T>& prop, bool write);
    static bool PlatformWritable(const SystemPropertyBase<T>& prop, bool write);
    static bool PlatformReadonly(const SystemPropertyBase<T>& prop, bool write);
    static bool AppReadonly(const SystemPropertyBase<T>& prop, bool write);

    std::optional<T> Get() const;
    void Set(const T& value);

    virtual ~SystemPropertyBase();

  protected:
    SystemPropertyBase(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                       std::optional<T> default_value, Accessor accessor, bool is_platform_prop);

    bool IsWriteOnce() const;
    std::string FullName() const;

  private:
    SystemPropertyBase<T>& operator=(const SystemPropertyBase<T>&) = delete;

    virtual std::optional<T> ParseValue(const std::string& value) const = 0;
    virtual std::string FormatValue(const T& value) const = 0;

    void CheckNamespace();

    struct SystemPropertyData;
    std::unique_ptr<SystemPropertyData> const data_;
};

class DoubleSystemProperty : public SystemPropertyBase<double> {
    friend class android::typedsystemproperty::PlatformProperties;

  public:
    DoubleSystemProperty(const std::string& name, PropertyNamespace prop_namy1espace,
                         bool writeonce, std::optional<double> default_value, Accessor accessor);
    ~DoubleSystemProperty();

  private:
    DoubleSystemProperty(const std::string& name, PropertyNamespace prop_namy1espace,
                         bool writeonce, std::optional<double> default_value, Accessor accessor,
                         bool is_platform_prop);
    std::optional<double> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const double& value) const override final;
};

class FloatSystemProperty : public SystemPropertyBase<float> {
    friend class android::typedsystemproperty::PlatformProperties;

  public:
    FloatSystemProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                        std::optional<float> default_value, Accessor accessor);
    ~FloatSystemProperty();

  private:
    FloatSystemProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                        std::optional<float> default_value, Accessor accessor,
                        bool is_platform_prop);
    std::optional<float> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const float& value) const override final;
};

class IntegerSystemProperty : public SystemPropertyBase<std::int32_t> {
    friend class android::typedsystemproperty::PlatformProperties;

  public:
    IntegerSystemProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                          std::optional<std::int32_t> default_value, Accessor accessor);
    ~IntegerSystemProperty();

  private:
    IntegerSystemProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                          std::optional<std::int32_t> default_value, Accessor accessor,
                          bool is_platform_prop);
    std::optional<std::int32_t> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const std::int32_t& value) const override final;
};

class LongSystemProperty : public SystemPropertyBase<std::int64_t> {
    friend class android::typedsystemproperty::PlatformProperties;

  public:
    LongSystemProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                       std::optional<std::int64_t> default_value, Accessor accessor);
    ~LongSystemProperty();

  private:
    LongSystemProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                       std::optional<std::int64_t> default_value, Accessor accessor,
                       bool is_platform_prop);
    std::optional<std::int64_t> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const std::int64_t& value) const override final;
};

class StringSystemProperty : public SystemPropertyBase<std::string> {
    friend class android::typedsystemproperty::PlatformProperties;

  public:
    StringSystemProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                         std::optional<std::string> default_value, Accessor accessor);
    ~StringSystemProperty();

  private:
    StringSystemProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                         std::optional<std::string> default_value, Accessor accessor,
                         bool is_platform_prop);
    std::optional<std::string> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const std::string& value) const override final;
};

class BooleanSystemProperty : public SystemPropertyBase<bool> {
    friend class android::typedsystemproperty::PlatformProperties;

  public:
    BooleanSystemProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                          std::optional<bool> default_value, Accessor accessor);
    ~BooleanSystemProperty();

  private:
    BooleanSystemProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                          std::optional<bool> default_value, Accessor accessor,
                          bool is_platform_prop);
    std::optional<bool> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const bool& value) const override final;
};

// We cannot let other modules derive an exported template class with their own
// type, (e.g. SystemPropertyBase<AwesomeEnumType>) unless we totally expose the
// implementation of the class in header files. Of course we don't want that, so
// The modules themselves should wrap this class to their own enum types.

class EnumSystemProperty : public SystemPropertyBase<std::int32_t> {
    friend class android::typedsystemproperty::PlatformProperties;

  public:
    EnumSystemProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                       std::optional<std::int32_t> default_value, Accessor accessor,
                       std::unordered_map<std::string, std::int32_t> enum_values);
    ~EnumSystemProperty();

  private:
    EnumSystemProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                       std::optional<std::int32_t> default_value, Accessor accessor,
                       std::unordered_map<std::string, std::int32_t> enum_values,
                       bool is_platform_prop);
    std::optional<std::int32_t> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const std::int32_t& value) const override final;

    class EnumSystemPropertyImpl;
    std::unique_ptr<EnumSystemPropertyImpl> const impl_;
};

extern template class SystemPropertyBase<bool>;
extern template class SystemPropertyBase<std::int32_t>;
extern template class SystemPropertyBase<std::int64_t>;
extern template class SystemPropertyBase<double>;
extern template class SystemPropertyBase<float>;
extern template class SystemPropertyBase<std::string>;

}  // namespace android::typedsystemproperty

#endif  // #ifndef SYSTEM_CORE_LIBTYPEDSYSPROP_TYPEDSYSTEMPROPERTY_H_

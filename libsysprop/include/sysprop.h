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

#ifndef SYSTEM_CORE_LIBSYSPROP_INCLUDE_SYSPROP_H_
#define SYSTEM_CORE_LIBSYSPROP_INCLUDE_SYSPROP_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

namespace android::os {
class PlatformProperties;
}

namespace android::sysprop {

enum class PropertyNamespace { Platform, Vendor, Odm };

// Predefined accessors
bool WorldReadonly(bool write);
bool PlatformWritable(bool write);
bool PlatformReadonly(bool write);
bool AppReadonly(bool write);

template <typename T>
class SystemPropertyBase {
    friend class android::os::PlatformProperties;

  public:
    using Accessor = std::function<bool(bool write)>;

    std::optional<T> Get() const;

    virtual ~SystemPropertyBase();

  protected:
    SystemPropertyBase(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                       std::optional<T> default_value, Accessor accessor, bool is_platform_prop);

    bool IsWriteOnce() const;
    const std::string& FullName() const;

  private:
    SystemPropertyBase<T>& operator=(const SystemPropertyBase<T>&) = delete;

    void Set(const T& value);

    virtual std::optional<T> ParseValue(const std::string& value) const = 0;
    virtual std::string FormatValue(const T& value) const = 0;

    void CheckNamespace();

    struct SystemPropertyData;
    std::unique_ptr<SystemPropertyData> const data_;
};

class DoubleProperty : public SystemPropertyBase<double> {
    friend class android::os::PlatformProperties;

  public:
    DoubleProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                   std::optional<double> default_value, Accessor accessor);
    ~DoubleProperty();

  private:
    DoubleProperty(const std::string& name, PropertyNamespace prop_namy1espace, bool writeonce,
                   std::optional<double> default_value, Accessor accessor, bool is_platform_prop);
    std::optional<double> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const double& value) const override final;
};

class FloatProperty : public SystemPropertyBase<float> {
    friend class android::os::PlatformProperties;

  public:
    FloatProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                  std::optional<float> default_value, Accessor accessor);
    ~FloatProperty();

  private:
    FloatProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                  std::optional<float> default_value, Accessor accessor, bool is_platform_prop);
    std::optional<float> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const float& value) const override final;
};

class IntegerProperty : public SystemPropertyBase<std::int32_t> {
    friend class android::os::PlatformProperties;

  public:
    IntegerProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                    std::optional<std::int32_t> default_value, Accessor accessor);
    ~IntegerProperty();

  private:
    IntegerProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                    std::optional<std::int32_t> default_value, Accessor accessor,
                    bool is_platform_prop);
    std::optional<std::int32_t> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const std::int32_t& value) const override final;
};

class LongProperty : public SystemPropertyBase<std::int64_t> {
    friend class android::os::PlatformProperties;

  public:
    LongProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                 std::optional<std::int64_t> default_value, Accessor accessor);
    ~LongProperty();

  private:
    LongProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                 std::optional<std::int64_t> default_value, Accessor accessor,
                 bool is_platform_prop);
    std::optional<std::int64_t> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const std::int64_t& value) const override final;
};

class StringProperty : public SystemPropertyBase<std::string> {
    friend class android::os::PlatformProperties;

  public:
    StringProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                   std::optional<std::string> default_value, Accessor accessor);
    ~StringProperty();

  private:
    StringProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                   std::optional<std::string> default_value, Accessor accessor,
                   bool is_platform_prop);
    std::optional<std::string> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const std::string& value) const override final;
};

class BooleanProperty : public SystemPropertyBase<bool> {
    friend class android::os::PlatformProperties;

  public:
    BooleanProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                    std::optional<bool> default_value, Accessor accessor);
    ~BooleanProperty();

  private:
    BooleanProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                    std::optional<bool> default_value, Accessor accessor, bool is_platform_prop);
    std::optional<bool> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const bool& value) const override final;
};

// We cannot let other modules derive an exported template class with their own
// type, (e.g. SystemPropertyBase<AwesomeEnumType>) unless we totally expose the
// implementation of the class in header files. Of course we don't want that, so
// The modules themselves should wrap this class to their own enum types.

class EnumProperty : public SystemPropertyBase<std::int32_t> {
    friend class android::os::PlatformProperties;

  public:
    EnumProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                 std::optional<std::int32_t> default_value, Accessor accessor,
                 std::unordered_map<std::string, std::int32_t> enum_values);
    ~EnumProperty();

  private:
    EnumProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                 std::optional<std::int32_t> default_value, Accessor accessor,
                 std::unordered_map<std::string, std::int32_t> enum_values, bool is_platform_prop);
    std::optional<std::int32_t> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const std::int32_t& value) const override final;

    class EnumPropertyImpl;
    std::unique_ptr<EnumPropertyImpl> const impl_;
};

extern template class SystemPropertyBase<bool>;
extern template class SystemPropertyBase<std::int32_t>;
extern template class SystemPropertyBase<std::int64_t>;
extern template class SystemPropertyBase<double>;
extern template class SystemPropertyBase<float>;
extern template class SystemPropertyBase<std::string>;

}  // namespace android::sysprop

#endif  // #ifndef SYSTEM_CORE_LIBSYSPROP_SYSPROP_H_

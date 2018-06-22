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
#include <optional>
#include <string>
#include <unordered_map>

namespace android::TypedSystemProperty {

constexpr char kNamespacePlatform[] = "";
constexpr char kNamespaceVendor[] = "vendor";
constexpr char kNamespaceOdm[] = "odm";

template <typename T>
class SystemPropertyBase {
  public:
    using Accessor = std::function<bool(const SystemPropertyBase<T>& prop, bool write)>;

    static bool WorldReadonly(const SystemPropertyBase<T>& prop, bool write);
    static bool PlatformWritable(const SystemPropertyBase<T>& prop, bool write);
    static bool PlatformReadonly(const SystemPropertyBase<T>& prop, bool write);
    static bool AppReadonly(const SystemPropertyBase<T>& prop, bool write);

    bool IsWriteOnce() const;
    std::string FullName() const;
    std::optional<T> Get() const;
    void Set(const T& value);

    virtual ~SystemPropertyBase();

  protected:
    // TODO: There may be a neater way to mark prop as "platform-defined prop"
    // other than passing a boolean to constructor which is very easy to fake.
    // But as this is not for security, We'll just trust user for now...
    SystemPropertyBase(const std::string& name, const std::string& namespace__, bool writeonce,
                       std::optional<T> default_value, Accessor accessor, bool is_platform_prop);

  private:
    struct SystemPropertyData;
    SystemPropertyData* const data_;

    SystemPropertyBase<T>& operator=(const SystemPropertyBase<T>&) = delete;
    virtual std::optional<T> ParseValue(const std::string& value) const = 0;
    virtual std::string FormatValue(const T& value) const = 0;

    void CheckNamespace();
};

class DoubleSystemProperty : public SystemPropertyBase<double> {
    using SystemPropertyBase<double>::SystemPropertyBase;

  private:
    std::optional<double> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const double& value) const override final;
};

class FloatSystemProperty : public SystemPropertyBase<float> {
    using SystemPropertyBase<float>::SystemPropertyBase;

  private:
    std::optional<float> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const float& value) const override final;
};

class IntegerSystemProperty : public SystemPropertyBase<std::int32_t> {
    using SystemPropertyBase<std::int32_t>::SystemPropertyBase;

  private:
    std::optional<std::int32_t> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const std::int32_t& value) const override final;
};

class LongSystemProperty : public SystemPropertyBase<std::int64_t> {
    using SystemPropertyBase<std::int64_t>::SystemPropertyBase;

  private:
    std::optional<std::int64_t> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const std::int64_t& value) const override final;
};

class StringSystemProperty : public SystemPropertyBase<std::string> {
    using SystemPropertyBase<std::string>::SystemPropertyBase;

  private:
    std::optional<std::string> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const std::string& value) const override final;
};

class BooleanSystemProperty : public SystemPropertyBase<bool> {
    using SystemPropertyBase<bool>::SystemPropertyBase;

  private:
    std::optional<bool> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const bool& value) const override final;
};

// We cannot let other modules derive an exported template class with their own
// type, (e.g. SystemPropertyBase<AwesomeEnumType>) unless we totally expose the
// implementation of the class in header files. Of course we don't want that, so
// The modules themselves should wrap this class to their own enum types.

class EnumSystemProperty : public SystemPropertyBase<std::int32_t> {
  protected:
    EnumSystemProperty(const std::string& name, const std::string& namespace__, bool writeonce,
                       std::optional<std::int32_t> default_value, Accessor accessor,
                       bool is_platform_prop,
                       std::unordered_map<std::string, std::int32_t> enum_values);

  private:
    std::unordered_map<std::string, std::int32_t> values_;
    std::unordered_map<std::int32_t, std::string> names_;

    std::optional<std::int32_t> ParseValue(const std::string& value) const override final;
    std::string FormatValue(const std::int32_t& value) const override final;
};

extern template class SystemPropertyBase<bool>;
extern template class SystemPropertyBase<std::int32_t>;
extern template class SystemPropertyBase<std::int64_t>;
extern template class SystemPropertyBase<double>;
extern template class SystemPropertyBase<float>;
extern template class SystemPropertyBase<std::string>;

}  // namespace android::TypedSystemProperty

#endif  // #ifndef SYSTEM_CORE_LIBTYPEDSYSPROP_TYPEDSYSTEMPROPERTY_H_

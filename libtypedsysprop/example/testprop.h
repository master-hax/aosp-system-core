#pragma once

#include <TypedSystemProperty.h>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace my::test::name::space {

using android::TypedSystemProperty::PropertyNamespace;

using android::TypedSystemProperty::BooleanSystemProperty;
using android::TypedSystemProperty::DoubleSystemProperty;
using android::TypedSystemProperty::EnumSystemProperty;
using android::TypedSystemProperty::FloatSystemProperty;
using android::TypedSystemProperty::IntegerSystemProperty;
using android::TypedSystemProperty::LongSystemProperty;
using android::TypedSystemProperty::StringSystemProperty;

class BooleanProperty final : public BooleanSystemProperty {
  public:
    BooleanProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                    std::optional<bool> default_value, Accessor accessor);
    using BooleanSystemProperty::Get;
};

class DoubleProperty final : public DoubleSystemProperty {
  public:
    DoubleProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                   std::optional<double> default_value, Accessor accessor);
    using DoubleSystemProperty::Get;
};

class FloatProperty final : public FloatSystemProperty {
  public:
    FloatProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                  std::optional<float> default_value, Accessor accessor);
    using FloatSystemProperty::Get;
};

class IntegerProperty final : public IntegerSystemProperty {
  public:
    IntegerProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                    std::optional<std::int32_t> default_value, Accessor accessor);
    using IntegerSystemProperty::Get;
};

class LongProperty final : public LongSystemProperty {
  public:
    LongProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                 std::optional<std::int64_t> default_value, Accessor accessor);
    using LongSystemProperty::Get;
};

class StringProperty final : public StringSystemProperty {
  public:
    StringProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                   std::optional<std::string> default_value, Accessor accessor);
    using StringSystemProperty::Get;
};

class EnumProperty final : public EnumSystemProperty {
  public:
    EnumProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                 std::optional<std::int32_t> default_value, Accessor accessor,
                 std::unordered_map<std::string, std::int32_t> enum_values);
    using EnumSystemProperty::Get;
};

extern DoubleProperty TEST_DOUBLE;
extern IntegerProperty TEST_INT;
extern StringProperty TEST_STRING;

enum test_enum_values {
    a,
    b,
    c,
    D,
    e,
    f,
    G,
};

class test_enum_Property final {
  private:
    EnumProperty prop_;

  public:
    test_enum_Property(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                       std::optional<test_enum_values> default_value,
                       EnumProperty::Accessor accessor,
                       std::unordered_map<std::string, test_enum_values> enum_values);

    std::optional<test_enum_values> Get() const;
};

extern test_enum_Property TEST_ENUM;
extern BooleanProperty TEST_BOOLEAN;
extern LongProperty LONGLONGLONGLONGLONGLONGLONGLONGLONG;

}  // namespace my::test::name::space

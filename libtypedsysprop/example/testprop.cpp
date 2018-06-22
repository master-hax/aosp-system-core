#include <testprop.h>

namespace my::test::name::space {

static const std::string kPrefix = "inseob.kim.";

using android::TypedSystemProperty::PropertyNamespace;

BooleanProperty::BooleanProperty(const std::string& name, PropertyNamespace prop_namespace,
                                 bool writeonce, std::optional<bool> default_value,
                                 Accessor accessor)
    : BooleanSystemProperty(name, prop_namespace, writeonce, std::move(default_value),
                            std::move(accessor), false) {}

DoubleProperty::DoubleProperty(const std::string& name, PropertyNamespace prop_namespace,
                               bool writeonce, std::optional<double> default_value,
                               Accessor accessor)
    : DoubleSystemProperty(name, prop_namespace, writeonce, std::move(default_value),
                           std::move(accessor), false) {}

FloatProperty::FloatProperty(const std::string& name, PropertyNamespace prop_namespace,
                             bool writeonce, std::optional<float> default_value, Accessor accessor)
    : FloatSystemProperty(name, prop_namespace, writeonce, std::move(default_value),
                          std::move(accessor), false) {}

IntegerProperty::IntegerProperty(const std::string& name, PropertyNamespace prop_namespace,
                                 bool writeonce, std::optional<std::int32_t> default_value,
                                 Accessor accessor)
    : IntegerSystemProperty(name, prop_namespace, writeonce, std::move(default_value),
                            std::move(accessor), false) {}

LongProperty::LongProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                           std::optional<std::int64_t> default_value, Accessor accessor)
    : LongSystemProperty(name, prop_namespace, writeonce, std::move(default_value),
                         std::move(accessor), false) {}

StringProperty::StringProperty(const std::string& name, PropertyNamespace prop_namespace,
                               bool writeonce, std::optional<std::string> default_value,
                               Accessor accessor)
    : StringSystemProperty(name, prop_namespace, writeonce, std::move(default_value),
                           std::move(accessor), false) {}

EnumProperty::EnumProperty(const std::string& name, PropertyNamespace prop_namespace, bool writeonce,
                           std::optional<std::int32_t> default_value, Accessor accessor,
                           std::unordered_map<std::string, std::int32_t> enum_values)
    : EnumSystemProperty(name, prop_namespace, writeonce, std::move(default_value),
                         std::move(accessor), false, std::move(enum_values)) {}

DoubleProperty TEST_DOUBLE{kPrefix + "test.double", PropertyNamespace::Platform, true,
                           std::make_optional(1e-30), DoubleProperty::WorldReadonly};

IntegerProperty TEST_INT{kPrefix + "test_int", PropertyNamespace::Platform, true,
                         std::make_optional(123456), IntegerProperty::WorldReadonly};

StringProperty TEST_STRING{kPrefix + "test.string", PropertyNamespace::Platform, true,
                           std::make_optional("hello?"), StringProperty::WorldReadonly};

test_enum_Property::test_enum_Property(const std::string& name, PropertyNamespace prop_namespace,
                                       bool writeonce, std::optional<test_enum_values> default_value,
                                       EnumProperty::Accessor accessor,
                                       std::unordered_map<std::string, test_enum_values> enum_values)
    : prop_(name, prop_namespace, writeonce, std::move(default_value), std::move(accessor),
            std::unordered_map<std::string, std::int32_t>{enum_values.begin(), enum_values.end()}) {
}

std::optional<test_enum_values> test_enum_Property::Get() const {
    std::optional<std::int32_t> res = prop_.Get();
    return res ? std::make_optional(static_cast<test_enum_values>(*res)) : std::nullopt;
}

test_enum_Property TEST_ENUM{kPrefix + "test.enum",
                             PropertyNamespace::Platform,
                             true,
                             std::nullopt,
                             EnumProperty::WorldReadonly,
                             {
                                     {"a", a},
                                     {"b", b},
                                     {"c", c},
                                     {"D", D},
                                     {"e", e},
                                     {"f", f},
                                     {"G", G},
                             }};

BooleanProperty TEST_BOOLEAN{kPrefix + "test_BOOLeaN", PropertyNamespace::Platform, true,
                             std::make_optional(true), BooleanProperty::WorldReadonly};

LongProperty LONGLONGLONGLONGLONGLONGLONGLONGLONG{
        kPrefix + "longlonglongLONGLONGlongLONGlongLONG", PropertyNamespace::Platform, true,
        std::make_optional(9223372036854775807), LongProperty::WorldReadonly};

}  // namespace my::test::name::space


#include <sstream>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <jsonpb/jsonpb.h>
#include <jsonpb/parse_message.h>

#include "test.pb.h"

using testing::HasSubstr;

namespace android {
namespace jsonpb {

class LibJsonpbVerifyTest : public ::testing::Test {};

// JSON field name matches Proto field name
TEST_F(LibJsonpbVerifyTest, NoJsonName1) {
    std::string json =
            "{\n"
            "    \"foo_bar\": \"foo_bar\",\n"
            "    \"barBaz\": \"barBaz\",\n"
            "    \"BazQux\": \"BazQux\",\n"
            "    \"QUX_QUUX\": \"QUX_QUUX\"\n"
            "\n}";
    auto object = JsonStringToMessage<NoJsonName>(json);
    ASSERT_TRUE(object.ok()) << object.error();

    EXPECT_EQ("foo_bar", object->foo_bar());
    EXPECT_EQ("barBaz", object->barbaz());
    EXPECT_EQ("BazQux", object->bazqux());
    EXPECT_EQ("QUX_QUUX", object->qux_quux());

    std::string error;
    EXPECT_TRUE(AllFieldsAreKnown(*object, json, &error)) << error;
}

template <typename T>
void TestNoImplicitJsonName(const std::string& field_name) {
    auto json_name = T{}.GetDescriptor()->FindFieldByName(field_name)->json_name();
    ASSERT_NE(field_name, json_name);
    std::string json = "{\"" + json_name + "\": \"test\"}";
    auto object = JsonStringToMessage<NoJsonName>(json);
    ASSERT_TRUE(object.ok()) << object.error();
    EXPECT_EQ("test", object->GetReflection()->GetString(
                              *object, object->GetDescriptor()->FindFieldByName(field_name)));
    std::string error;
    EXPECT_FALSE(AllFieldsAreKnown(*object, json, &error)) << "Should return false";
    EXPECT_THAT(error, HasSubstr("unknown keys"));
    EXPECT_THAT(error, HasSubstr(json_name));
}

// JSON field name is lower camel case of Proto field name; AllFieldsAreKnown should return false.
TEST_F(LibJsonpbVerifyTest, NoJsonName2) {
    TestNoImplicitJsonName<NoJsonName>("foo_bar");
}

TEST_F(LibJsonpbVerifyTest, NoJsonName3) {
    TestNoImplicitJsonName<NoJsonName>("BazQux");
}

TEST_F(LibJsonpbVerifyTest, NoJsonName4) {
    TestNoImplicitJsonName<NoJsonName>("QUX_QUUX");
}

int main(int argc, char** argv) {
    using ::testing::AddGlobalTestEnvironment;
    using ::testing::InitGoogleTest;

    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

}  // namespace jsonpb
}  // namespace android

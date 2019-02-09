
#pragma once

#include <memory>
#include <string>

#include <android-base/file.h>
#include <android-base/strings.h>
#include <gtest/gtest.h>
#include <json/reader.h>
#include <jsonpb/jsonpb.h>
#include <jsonpb/parse_message.h>

namespace android {
namespace jsonpb {

class JsonSchemaTestEnvironment : public ::testing::Environment {
  public:
    std::string root_;
    bool verbose_ = false;
};
extern JsonSchemaTestEnvironment* gJsonSchemaTestEnvironment;

template <typename TestParam>
class JsonSchemaTest : public ::testing::Test {
  public:
    void SetUp() override {
        ASSERT_NE(nullptr, gJsonSchemaTestEnvironment) << "Environment not initialized.";

        TestParam param;

        file_path_ = gJsonSchemaTestEnvironment->root_ + param.path_;
        ASSERT_TRUE(android::base::ReadFileToString(file_path_, &json_))
                << "Cannot read " << file_path_;
        auto object_ = JsonStringToMessage<typename TestParam::Prototype>(json_);
        ASSERT_TRUE(object_.ok()) << "Invalid format of file " << file_path_ << ": "
                                  << object_.error();
        if (gJsonSchemaTestEnvironment->verbose_) {
            std::cout << object_->DebugString() << std::endl;
        }
    }

    std::string file_path_;
    std::string json_;
    ErrorOr<typename TestParam::Prototype> object_;
};
TYPED_TEST_SUITE_P(JsonSchemaTest);

// Test that the JSON file has no fields unknown by the schema. See AllFieldsAreKnown() for
// more details.
TYPED_TEST_P(JsonSchemaTest, NoUnknownFields) {
    std::stringstream ss;
    EXPECT_TRUE(AllFieldsAreKnown(*this->object_, this->json, &ss))
            << "File: " << this->file_path_ << ": " << ss.rdbuf();
}

REGISTER_TYPED_TEST_SUITE_P(JsonSchemaTest, NoUnknownFields);

}  // namespace jsonpb
}  // namespace android

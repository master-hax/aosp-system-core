#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include <android-base/strings.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/descriptor.pb.h>
#include <google/protobuf/message.h>
#include <google/protobuf/reflection.h>
#include <json/reader.h>
#include <jsonpb/parse_message.h>

namespace android {
namespace jsonpb {

using google::protobuf::FieldDescriptor;
using google::protobuf::FieldDescriptorProto;
using google::protobuf::Message;

// Return |json_name| of the field. If it is not set, the name of the field.
const std::string& GetJsonName(const FieldDescriptor& field_descriptor) {
    // The current version of libprotobuf does not define FieldDescriptor::has_json_name() yet.
    // Use a workaround.
    // TODO: use field_descriptor.has_json_name() when libprotobuf version is bumped.
    FieldDescriptorProto proto;
    field_descriptor.CopyTo(&proto);
    return proto.has_json_name() ? field_descriptor.json_name() : field_descriptor.name();
}

bool AllFieldsAreKnown(const Message& message, const Json::Value& json,
                       std::vector<std::string>* path, std::stringstream* error) {
    if (!json.isObject()) {
        *error << base::Join(*path, ".") << ": Not a JSON object\n";
        return false;
    }
    auto&& descriptor = message.GetDescriptor();

    // TODO check syntax == proto3

    auto json_members = json.getMemberNames();
    std::set<std::string> json_keys{json_members.begin(), json_members.end()};

    std::set<std::string> known_keys;
    for (int i = 0; i < descriptor->field_count(); ++i) {
        known_keys.insert(GetJsonName(*descriptor->field(i)));
    }

    std::set<std::string> unknown_keys;
    std::set_difference(json_keys.begin(), json_keys.end(), known_keys.begin(), known_keys.end(),
                        std::inserter(unknown_keys, unknown_keys.begin()));

    if (!unknown_keys.empty()) {
        *error << base::Join(*path, ".") << ": contains unknown keys: ["
               << base::Join(unknown_keys, ", ") << "]. Keys must be a known field name of "
               << descriptor->full_name() << "(or its json_name option if set): ["
               << base::Join(known_keys, ", ") << "]\n";
        return false;
    }

    bool success = true;

    // Check message fields.
    auto&& reflection = message.GetReflection();
    std::vector<const FieldDescriptor*> set_field_descriptors;
    reflection->ListFields(message, &set_field_descriptors);
    for (auto&& field_descriptor : set_field_descriptors) {
        if (field_descriptor->cpp_type() != FieldDescriptor::CppType::CPPTYPE_MESSAGE) {
            continue;
        }

        const std::string& json_name = GetJsonName(*field_descriptor);
        const Json::Value& json_value = json[json_name];

        if (field_descriptor->is_repeated()) {
            auto&& fields = reflection->GetRepeatedFieldRef<Message>(message, field_descriptor);
            std::unique_ptr<Message> scratch_space(fields.NewMessage());
            for (int i = 0; i < fields.size(); ++i) {
                path->push_back(json_name + "[" + std::to_string(i) + "]");
                auto res = AllFieldsAreKnown(fields.Get(i, scratch_space.get()), json_value[i],
                                             path, error);
                path->pop_back();
                if (!res) {
                    success = false;
                }
            }
        } else {
            auto&& field = reflection->GetMessage(message, field_descriptor);
            path->push_back(json_name);
            auto res = AllFieldsAreKnown(field, json_value, path, error);
            path->pop_back();
            if (!res) {
                success = false;
            }
        }
    }
    return success;
}

bool AllFieldsAreKnown(const google::protobuf::Message& message, const std::string& json,
                       std::stringstream* error) {
    Json::Reader reader;
    Json::Value value;
    if (!reader.parse(json, value)) {
        *error << reader.getFormattedErrorMessages();
        return false;
    }

    std::vector<std::string> json_tree_path{"<root>"};
    if (!AllFieldsAreKnown(message, value, &json_tree_path, error)) {
        return false;
    }

    error->clear();
    return true;
}

bool AllFieldsAreKnown(const google::protobuf::Message& message, const std::string& json,
                       std::string* error) {
    std::stringstream ss;
    bool res = AllFieldsAreKnown(message, json, &ss);
    *error = ss.str();
    return res;
}

}  // namespace jsonpb
}  // namespace android

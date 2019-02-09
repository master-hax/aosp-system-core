
#pragma once

#include <sstream>
#include <string>
#include <vector>

#include <google/protobuf/message.h>
#include <json/value.h>
#include <jsonpb/parse_message.h>

namespace android {
namespace jsonpb {

// Ensure that the JSON file has no unknown fields that is not defined in proto. Note that
// proto3 always discard unknown fields (until version 3.5) and return empty set for
// Reflection::GetUnknownFields (until version 3.5). Hence, we check unknown fields manually
// by traversing all fields of the tree and comparing it against known fields of |message|.
//
// This test ensures that all fields in the JSON file is understood by the schema. For example,
// if a new field "foo" is added to cgroups.json but not to cgroups.proto, libprocessgroup
// could technically read the value of "foo" by using other libraries that parse JSON strings,
// effectively working around the schema.
//
// This test also ensures that the parser does not use alternative key names. For example,
// if the proto file states:
// message Foo { string foo_bar = 1; string bar_baz = 2 [json_name = "BarBaz"]; }
// Then the parser accepts "foo_bar" "fooBar", "bar_baz", "BarBaz" as valid key names.
// Here, we enforce that the JSON file must use "foo_bar" and "BarBaz".
//
// Requiring this avoids surprises like:
//     message Foo { string FooBar = 1; }
//     { "fooBar" : "s" }
// conforms with the schema, because libprotobuf accept "fooBar" as a valid key.
// The correct schema should be:
//     message Foo { string foo_bar = 1 [json_name="fooBar"]; }
//
// Params:
//    path: path to navigate inside JSON tree. For example, {"foo", "bar"} for the value "string" in
//          {"foo": {"bar" : "string"}}
bool AllFieldsAreKnown(const google::protobuf::Message& message, const std::string& json,
                       std::stringstream* error);

bool AllFieldsAreKnown(const google::protobuf::Message& message, const std::string& json,
                       std::string* error);

}  // namespace jsonpb
}  // namespace android

// Copyright (C) 2020 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <map>
#include <string>
#include <string_view>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>

// Utilities for using a protobuf definition to fuzz APIs in a class.
// Terms:
// The "fuzzed class" is the C++ class definition whose functions are fuzzed.
// The "fuzzed object" is an instantiated object of the fuzzed class. It is
//   typically created and destroyed for each test run.
// An "action" is an operation on the fuzzed object that may mutate its state.
//   This typically involves one function call into the fuzzed object.

namespace android::fuzz {

// CHECK(value) << msg
void CheckInternal(bool value, std::string_view msg);

// Get the oneof descriptor inside Action
const google::protobuf::OneofDescriptor* GetProtoValueDescriptor(
        const google::protobuf::Descriptor* action_desc);

template <typename Class>
using FunctionMapImpl =
        std::map<int, std::function<void(Class*, const google::protobuf::Message& action_proto,
                                         const google::protobuf::FieldDescriptor* field_desc)>>;

template <typename Class>
class FunctionMap : public FunctionMapImpl<Class> {
  public:
    void CheckEmplace(typename FunctionMapImpl<Class>::key_type key,
                      typename FunctionMapImpl<Class>::mapped_type&& value) {
        auto [it, inserted] = this->emplace(key, std::move(value));
        CheckInternal(inserted,
                      "Multiple implementation registered for tag number " + std::to_string(key));
    }
};

template <typename Action>
int CheckConsistency() {
    const auto* function_map = Action::GetFunctionMap();
    const auto* action_value_desc = GetProtoValueDescriptor(Action::Proto::GetDescriptor());

    for (int field_index = 0; field_index < action_value_desc->field_count(); ++field_index) {
        const auto* field_desc = action_value_desc->field(field_index);
        CheckInternal(function_map->find(field_desc->number()) != function_map->end(),
                      "Missing impl for function " + field_desc->camelcase_name());
    }
    return 0;
}

template <typename Action>
void ExecuteActionProto(typename Action::Class* module,
                        const typename Action::Proto& action_proto) {
    static auto* action_value_desc = GetProtoValueDescriptor(Action::Proto::GetDescriptor());

    auto* action_refl = Action::Proto::GetReflection();
    if (!action_refl->HasOneof(action_proto, action_value_desc)) {
        return;
    }

    const auto* field_desc = action_refl->GetOneofFieldDescriptor(action_proto, action_value_desc);
    auto number = field_desc->number();
    const auto& map = *Action::GetFunctionMap();
    auto it = map.find(number);
    CheckInternal(it != map.end(), "Missing impl for function " + field_desc->camelcase_name());
    const auto& func = it->second;
    func(module, action_proto, field_desc);
}

template <typename Action>
void ExecuteAllActionProtos(
        typename Action::Class* module,
        const google::protobuf::RepeatedPtrField<typename Action::Proto>& action_protos) {
    for (const auto& proto : action_protos) {
        ExecuteActionProto<Action>(module, proto);
    }
}

// Safely cast message to T. Returns a pointer to message if cast successfully, otherwise nullptr.
template <typename T>
const T* SafeCast(const google::protobuf::Message& message) {
    if (message.GetDescriptor() != T::GetDescriptor()) {
        return nullptr;
    }
    return static_cast<const T*>(&message);
}

// Cast message to const T&. Abort if type mismatch.
template <typename T>
const T& CheckedCast(const google::protobuf::Message& message) {
    const auto* ptr = SafeCast<T>(message);
    CheckInternal(ptr, "Cannot cast " + message.GetDescriptor()->name() + " to " +
                               T::GetDescriptor()->name());
    return *ptr;
}

template <typename T, typename Unused = void>
struct ArgReader;

template <typename T>
struct ArgReader<T, typename std::enable_if_t<std::is_base_of_v<google::protobuf::Message, T>>> {
    static const T& Get(const google::protobuf::Message& action_proto,
                        const google::protobuf::FieldDescriptor* field_desc) {
        return CheckedCast<std::remove_reference_t<T>>(
                action_proto.GetReflection()->GetMessage(action_proto, field_desc));
    }
};

template <>
struct ArgReader<std::string> {
    // A wrapper over std::string that may or may not own it. GetStringReference may return
    // a string reference within the protobuf message or into the scratch space. In the latter case,
    // return the scratch space as well.
    struct MaybeOwnStringReference {
        MaybeOwnStringReference(const google::protobuf::Message& action_proto,
                                const google::protobuf::FieldDescriptor* field_desc) {
            string_ptr_ = &action_proto.GetReflection()->GetStringReference(
                    action_proto, field_desc, &owned_string_);
        }
        operator const std::string&() { return *string_ptr_; }

      private:
        std::string owned_string_;
        const std::string* string_ptr_ = nullptr;
    };
    using ret_type = MaybeOwnStringReference;
    static MaybeOwnStringReference Get(const google::protobuf::Message& action_proto,
                                       const google::protobuf::FieldDescriptor* field_desc) {
        return MaybeOwnStringReference(action_proto, field_desc);
    }
};

template <>
struct ArgReader<bool> {
    static bool Get(const google::protobuf::Message& action_proto,
                    const google::protobuf::FieldDescriptor* field_desc) {
        return action_proto.GetReflection()->GetBool(action_proto, field_desc);
    }
};

// Used to indicate that no args is expected from the protobuf message.
struct Void {};

template <>
struct ArgReader<Void> {
    // Can't have void arguments, so just use an unused boolean.
    static Void Get(const google::protobuf::Message&, const google::protobuf::FieldDescriptor*) {
        return {};
    }
};

// Helper to get the type of "Foo foo". Example:
// ArgTypeTraits<void(const Foo& foo)>::argument_type -> const Foo&
template <typename T>
struct ArgTypeTraits;
template <typename Arg>
struct ArgTypeTraits<void(Arg)> {
    // This trick won't work in C++20, but it works for now.
    using argument_type = typename std::function<void(Arg)>::argument_type;
    using plain_type = std::remove_const_t<std::remove_reference_t<argument_type>>;
};

}  // namespace android::fuzz

// Fuzz existing C++ class, ClassType, with a collection of functions under the name Action.
//
// Prerequisite: ActionProto must be defined in Protobuf to describe possible actions:
// message FooActionProto {
//     message NoArgs {}
//     oneof value {
//         bool do_foo = 1;
//         NoArgs do_bar = 1;
//     }
// }
// Use it to fuzz a C++ class Foo by doing the following:
//   FUZZ_CLASS(Foo, FooAction)
// After linking functions of Foo to FooAction, execute all actions by:
//   FooAction::ExecuteAll(foo_object, action_protos)
#define FUZZ_CLASS(ClassType, Action)                                                            \
    class Action {                                                                               \
      public:                                                                                    \
        using Proto = Action##Proto;                                                             \
        using Class = ClassType;                                                                 \
        using FunctionMap = android::fuzz::FunctionMap<Class>;                                   \
        static FunctionMap* GetFunctionMap() {                                                   \
            static Action::FunctionMap map;                                                      \
            return &map;                                                                         \
        }                                                                                        \
        static void ExecuteAll(Class* module,                                                    \
                               const google::protobuf::RepeatedPtrField<Proto>& action_protos) { \
            [[maybe_unused]] static int consistent = android::fuzz::CheckConsistency<Action>();  \
            android::fuzz::ExecuteAllActionProtos<Action>(module, action_protos);                \
        }                                                                                        \
    }

#define FUZZ_FUNCTION_CLASS_NAME(Action, FunctionName) Action##_##FunctionName
#define FUZZ_FUNCTION_TAG_NAME(FunctionName) k##FunctionName

// Implement an action defined in protobuf. Example:
// message FooActionProto {
//     oneof value {
//         bool do_foo = 1;
//     }
// }
// class Foo { public: void DoAwesomeFoo(bool arg); };
// FUZZ_OBJECT(FooAction, Foo);
// FUZZ_FUNCTION(FooAction, DoFoo, module, bool arg) {
//   module->DoAwesomeFoo(arg);
// }
// The name DoFoo is the camel case name of the action in protobuf definition of FooActionProto.
#define FUZZ_FUNCTION(Action, FunctionName, module, args)                                          \
    class FUZZ_FUNCTION_CLASS_NAME(Action, FunctionName) {                                         \
      public:                                                                                      \
        static void ImplBody(Action::Class*, args);                                                \
                                                                                                   \
      private:                                                                                     \
        static void ImplBodyWithField(Action::Class*,                                              \
                                      const google::protobuf::Message& action_proto,               \
                                      const google::protobuf::FieldDescriptor* field_desc);        \
        static bool registered_;                                                                   \
    };                                                                                             \
    auto FUZZ_FUNCTION_CLASS_NAME(Action, FunctionName)::registered_ = ([] {                       \
        auto* api_map = Action::GetFunctionMap();                                                  \
        api_map->CheckEmplace(Action::Proto::ValueCase::FUZZ_FUNCTION_TAG_NAME(FunctionName),      \
                              &FUZZ_FUNCTION_CLASS_NAME(Action, FunctionName)::ImplBodyWithField); \
        return true;                                                                               \
    })();                                                                                          \
    void FUZZ_FUNCTION_CLASS_NAME(Action, FunctionName)::ImplBodyWithField(                        \
            Action::Class* module, const google::protobuf::Message& action_proto,                  \
            const google::protobuf::FieldDescriptor* field_desc) {                                 \
        ImplBody(module,                                                                           \
                 android::fuzz::ArgReader<                                                         \
                         android::fuzz::ArgTypeTraits<void(args)>::plain_type>::Get(action_proto,  \
                                                                                    field_desc));  \
    }                                                                                              \
    void FUZZ_FUNCTION_CLASS_NAME(Action, FunctionName)::ImplBody(                                 \
            [[maybe_unused]] Action::Class* module, [[maybe_unused]] args)

// Implement a simple action by linking it to the function with the same name. Example:
// message FooActionProto {
//     message NoArgs {}
//     oneof value {
//         NoArgs do_bar = 1;
//     }
// }
// class Foo { public void DoBar(); };
// FUZZ_OBJECT(FooAction, Foo);
// FUZZ_FUNCTION(FooAction, DoBar);
// The name DoBar is the camel case name of the action in protobuf definition of FooActionProto, and
// also the name of the function of Foo.
#define FUZZ_SIMPLE_FUNCTION(Action, FunctionName) \
    FUZZ_FUNCTION(Action, FunctionName, module, Void) { (void)module->FunctionName(); }

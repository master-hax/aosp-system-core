
#pragma once

#include <string>
#include <variant>

#include <android-base/logging.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/util/json_util.h>
#include <google/protobuf/util/type_resolver_util.h>

namespace android {
namespace jsonpb {

static constexpr char kTypeUrlPrefix[] = "type.googleapis.com";

static inline std::string GetTypeUrl(const google::protobuf::Descriptor* message) {
    return std::string(kTypeUrlPrefix) + "/" + message->full_name();
}

template <typename T>
struct ErrorOr {
    template <class... Args>
    explicit ErrorOr(Args&&... args) : data_(kIndex1, std::forward<Args>(args)...) {}
    T& operator*() {
        CHECK(ok());
        return *std::get_if<1u>(&data_);
    }
    const T& operator*() const {
        CHECK(ok());
        return *std::get_if<1u>(&data_);
    }
    T* operator->() {
        CHECK(ok());
        return std::get_if<1u>(&data_);
    }
    const T* operator->() const {
        CHECK(ok());
        return std::get_if<1u>(&data_);
    }
    const std::string& error() const {
        CHECK(!ok());
        return *std::get_if<0u>(&data_);
    }
    bool ok() const { return data_.index() != 0; }
    static ErrorOr<T> MakeError(const std::string& message) {
        return ErrorOr<T>(message, Tag::kDummy);
    }

  private:
    enum class Tag { kDummy };
    static constexpr std::in_place_index_t<0> kIndex0{};
    static constexpr std::in_place_index_t<1> kIndex1{};
    ErrorOr(const std::string& msg, Tag) : data_(kIndex0, msg) {}

    std::variant<std::string, T> data_;
};

// TODO: JsonStringToMessage is a newly added function in protobuf
// and is not yet available in the android tree. Replace this function with
// https://developers.google.com/protocol-buffers/docs/reference/cpp/
// google.protobuf.util.json_util#JsonStringToMessage.details
// as and when the android tree gets updated
template <typename T>
ErrorOr<T> JsonStringToMessage(const std::string& content) {
    using google::protobuf::DescriptorPool;
    using google::protobuf::scoped_ptr;
    using google::protobuf::util::NewTypeResolverForDescriptorPool;
    using google::protobuf::util::TypeResolver;

    ErrorOr<T> ret;
    scoped_ptr<TypeResolver> resolver(
            NewTypeResolverForDescriptorPool(kTypeUrlPrefix, DescriptorPool::generated_pool()));

    std::string binary;
    auto status =
            JsonToBinaryString(resolver.get(), GetTypeUrl(ret->GetDescriptor()), content, &binary);
    if (!status.ok()) {
        return ErrorOr<T>::MakeError(status.error_message().as_string());
    }
    if (!ret->ParseFromString(binary)) {
        return ErrorOr<T>::MakeError("Fail to parse.");
    }
    return ErrorOr<T>(std::move(ret));
}

}  // namespace jsonpb
}  // namespace android

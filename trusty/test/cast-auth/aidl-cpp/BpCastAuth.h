#pragma once
#include <optional>

#include <lib/binder/android-base/unique_fd.h>
#include <ICastAuth.h>

namespace aidl {
class BpCastAuth : public ICastAuth {
public:
  BpCastAuth() = delete;
  int ProvisionKey(const ::trusty::aidl::Payload& req_payload) override;
  int SignHash(const ::trusty::aidl::Payload& req_payload, ::trusty::aidl::Payload* resp_payload) override;
  static int connect(std::optional<BpCastAuth>&, const char*, uint32_t);
private:
  BpCastAuth(::android::base::unique_fd chan) : mChan(std::move(chan)) {}
  ::android::base::unique_fd mChan;
};
}  // namespace aidl

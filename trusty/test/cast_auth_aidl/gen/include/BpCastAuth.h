#pragma once

#include <ICastAuth.h>
#include <binder/IBinder.h>
#include <binder/IInterface.h>
#include <utils/Errors.h>

class BpCastAuth : public ::android::BpInterface<ICastAuth> {
  public:
    explicit BpCastAuth(const ::android::sp<::android::IBinder>& _aidl_impl);
    virtual ~BpCastAuth() = default;
    ::android::binder::Status ProvisionKey(const ::std::vector<uint8_t>& wrapped_key) override;
    ::android::binder::Status SignHash(const ::std::vector<uint8_t>& hash,
                                       ::std::vector<uint8_t>* signature) override;
};  // class BpCastAuth

#pragma once

#include <ICastAuth.h>
#include <binder/IInterface.h>

class BnCastAuth : public ::android::BnInterface<ICastAuth> {
  public:
    static constexpr uint32_t TRANSACTION_ProvisionKey =
            ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
    static constexpr uint32_t TRANSACTION_SignHash = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
    explicit BnCastAuth();
    ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data,
                                   ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
};  // class BnCastAuth

class ICastAuthDelegator : public BnCastAuth {
  public:
    explicit ICastAuthDelegator(::android::sp<ICastAuth>& impl) : _aidl_delegate(impl) {}

    ::android::binder::Status ProvisionKey(const ::std::vector<uint8_t>& wrapped_key) override {
        return _aidl_delegate->ProvisionKey(wrapped_key);
    }
    ::android::binder::Status SignHash(const ::std::vector<uint8_t>& hash,
                                       ::std::vector<uint8_t>* signature) override {
        return _aidl_delegate->SignHash(hash, signature);
    }

  private:
    ::android::sp<ICastAuth> _aidl_delegate;
};  // class ICastAuthDelegator

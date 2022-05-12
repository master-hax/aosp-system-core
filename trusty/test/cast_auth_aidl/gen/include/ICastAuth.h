#pragma once

#include <binder/IBinder.h>
#include <binder/IInterface.h>
#include <binder/Status.h>
#include <utils/StrongPointer.h>
#include <cstdint>
#include <string>
#include <vector>

class ICastAuth : public ::android::IInterface {
  public:
    DECLARE_META_INTERFACE(CastAuth)
    static const ::std::string& PORT();
    virtual ::android::binder::Status ProvisionKey(const ::std::vector<uint8_t>& wrapped_key) = 0;
    virtual ::android::binder::Status SignHash(const ::std::vector<uint8_t>& hash,
                                               ::std::vector<uint8_t>* signature) = 0;
};  // class ICastAuth

class ICastAuthDefault : public ICastAuth {
  public:
    ::android::IBinder* onAsBinder() override { return nullptr; }
    ::android::binder::Status ProvisionKey(const ::std::vector<uint8_t>& /*wrapped_key*/) override {
        return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
    }
    ::android::binder::Status SignHash(const ::std::vector<uint8_t>& /*hash*/,
                                       ::std::vector<uint8_t>* /*signature*/) override {
        return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
    }
};  // class ICastAuthDefault

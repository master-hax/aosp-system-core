#include <BpCastAuth.h>
#include <ICastAuth.h>
DO_NOT_DIRECTLY_USE_ME_IMPLEMENT_META_INTERFACE(CastAuth, "ICastAuth")
const ::std::string& ICastAuth::PORT() {
    static const ::std::string value("com.android.trusty.cast_auth");
    return value;
}
#include <BnCastAuth.h>
#include <BpCastAuth.h>
#include <android-base/macros.h>
#include <binder/Parcel.h>

BpCastAuth::BpCastAuth(const ::android::sp<::android::IBinder>& _aidl_impl)
    : BpInterface<ICastAuth>(_aidl_impl) {}

::android::binder::Status BpCastAuth::ProvisionKey(const ::std::vector<uint8_t>& wrapped_key) {
    ::android::Parcel _aidl_data;
    _aidl_data.markForBinder(remoteStrong());
    ::android::Parcel _aidl_reply;
    ::android::status_t _aidl_ret_status = ::android::OK;
    ::android::binder::Status _aidl_status;
    _aidl_ret_status = _aidl_data.writeInterfaceToken(getInterfaceDescriptor());
    if (((_aidl_ret_status) != (::android::OK))) {
        goto _aidl_error;
    }
    _aidl_ret_status = _aidl_data.writeByteVector(wrapped_key);
    if (((_aidl_ret_status) != (::android::OK))) {
        goto _aidl_error;
    }
    _aidl_ret_status =
            remote()->transact(BnCastAuth::TRANSACTION_ProvisionKey, _aidl_data, &_aidl_reply, 0);
    if (UNLIKELY(_aidl_ret_status == ::android::UNKNOWN_TRANSACTION &&
                 ICastAuth::getDefaultImpl())) {
        return ICastAuth::getDefaultImpl()->ProvisionKey(wrapped_key);
    }
    if (((_aidl_ret_status) != (::android::OK))) {
        goto _aidl_error;
    }
    _aidl_ret_status = _aidl_status.readFromParcel(_aidl_reply);
    if (((_aidl_ret_status) != (::android::OK))) {
        goto _aidl_error;
    }
    if (!_aidl_status.isOk()) {
        return _aidl_status;
    }
_aidl_error:
    _aidl_status.setFromStatusT(_aidl_ret_status);
    return _aidl_status;
}

::android::binder::Status BpCastAuth::SignHash(const ::std::vector<uint8_t>& hash,
                                               ::std::vector<uint8_t>* signature) {
    ::android::Parcel _aidl_data;
    _aidl_data.markForBinder(remoteStrong());
    ::android::Parcel _aidl_reply;
    ::android::status_t _aidl_ret_status = ::android::OK;
    ::android::binder::Status _aidl_status;
    _aidl_ret_status = _aidl_data.writeInterfaceToken(getInterfaceDescriptor());
    if (((_aidl_ret_status) != (::android::OK))) {
        goto _aidl_error;
    }
    _aidl_ret_status = _aidl_data.writeByteVector(hash);
    if (((_aidl_ret_status) != (::android::OK))) {
        goto _aidl_error;
    }
    _aidl_ret_status = _aidl_data.writeVectorSize(*signature);
    if (((_aidl_ret_status) != (::android::OK))) {
        goto _aidl_error;
    }
    _aidl_ret_status =
            remote()->transact(BnCastAuth::TRANSACTION_SignHash, _aidl_data, &_aidl_reply, 0);
    if (UNLIKELY(_aidl_ret_status == ::android::UNKNOWN_TRANSACTION &&
                 ICastAuth::getDefaultImpl())) {
        return ICastAuth::getDefaultImpl()->SignHash(hash, signature);
    }
    if (((_aidl_ret_status) != (::android::OK))) {
        goto _aidl_error;
    }
    _aidl_ret_status = _aidl_status.readFromParcel(_aidl_reply);
    if (((_aidl_ret_status) != (::android::OK))) {
        goto _aidl_error;
    }
    if (!_aidl_status.isOk()) {
        return _aidl_status;
    }
    _aidl_ret_status = _aidl_reply.readByteVector(signature);
    if (((_aidl_ret_status) != (::android::OK))) {
        goto _aidl_error;
    }
_aidl_error:
    _aidl_status.setFromStatusT(_aidl_ret_status);
    return _aidl_status;
}

#include <BnCastAuth.h>
#include <binder/Parcel.h>
#include <binder/Stability.h>

BnCastAuth::BnCastAuth() {
    ::android::internal::Stability::markCompilationUnit(this);
}

::android::status_t BnCastAuth::onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data,
                                           ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) {
    ::android::status_t _aidl_ret_status = ::android::OK;
    switch (_aidl_code) {
        case BnCastAuth::TRANSACTION_ProvisionKey: {
            ::std::vector<uint8_t> in_wrapped_key;
            if (!(_aidl_data.checkInterface(this))) {
                _aidl_ret_status = ::android::BAD_TYPE;
                break;
            }
            _aidl_ret_status = _aidl_data.readByteVector(&in_wrapped_key);
            if (((_aidl_ret_status) != (::android::OK))) {
                break;
            }
            if (auto st = _aidl_data.enforceNoDataAvail(); !st.isOk()) {
                _aidl_ret_status = st.writeToParcel(_aidl_reply);
                break;
            }
            ::android::binder::Status _aidl_status(ProvisionKey(in_wrapped_key));
            _aidl_ret_status = _aidl_status.writeToParcel(_aidl_reply);
            if (((_aidl_ret_status) != (::android::OK))) {
                break;
            }
            if (!_aidl_status.isOk()) {
                break;
            }
        } break;
        case BnCastAuth::TRANSACTION_SignHash: {
            ::std::vector<uint8_t> in_hash;
            ::std::vector<uint8_t> out_signature;
            if (!(_aidl_data.checkInterface(this))) {
                _aidl_ret_status = ::android::BAD_TYPE;
                break;
            }
            _aidl_ret_status = _aidl_data.readByteVector(&in_hash);
            if (((_aidl_ret_status) != (::android::OK))) {
                break;
            }
            _aidl_ret_status = _aidl_data.resizeOutVector(&out_signature);
            if (((_aidl_ret_status) != (::android::OK))) {
                break;
            }
            if (auto st = _aidl_data.enforceNoDataAvail(); !st.isOk()) {
                _aidl_ret_status = st.writeToParcel(_aidl_reply);
                break;
            }
            ::android::binder::Status _aidl_status(SignHash(in_hash, &out_signature));
            _aidl_ret_status = _aidl_status.writeToParcel(_aidl_reply);
            if (((_aidl_ret_status) != (::android::OK))) {
                break;
            }
            if (!_aidl_status.isOk()) {
                break;
            }
            _aidl_ret_status = _aidl_reply->writeByteVector(out_signature);
            if (((_aidl_ret_status) != (::android::OK))) {
                break;
            }
        } break;
        default: {
            _aidl_ret_status = ::android::BBinder::onTransact(_aidl_code, _aidl_data, _aidl_reply,
                                                              _aidl_flags);
        } break;
    }
    if (_aidl_ret_status == ::android::UNEXPECTED_NULL) {
        _aidl_ret_status = ::android::binder::Status::fromExceptionCode(
                                   ::android::binder::Status::EX_NULL_POINTER)
                                   .writeOverParcel(_aidl_reply);
    }
    return _aidl_ret_status;
}

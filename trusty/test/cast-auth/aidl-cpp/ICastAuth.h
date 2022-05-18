#pragma once
//#include <array>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#ifdef __TRUSTY__
#include <lk/compiler.h>
#else
#define __PACKED __attribute__((packed))
#endif

#include <lib/binder/Binder.h>
#include <lib/binder/Errors.h>

namespace aidl {
class ICastAuth {
public:
  virtual ~ICastAuth() {}
  virtual int ProvisionKey(const ::trusty::aidl::Payload& req_payload) = 0;
  virtual int SignHash(const ::trusty::aidl::Payload& req_payload, ::trusty::aidl::Payload* resp_payload) = 0;
  static constexpr char PORT[] = "com.android.trusty.cast-auth";
  enum : uint32_t {
    REQ_SHIFT = 1,
    RESP_BIT = 1,
    CMD_ProvisionKey = (0 << REQ_SHIFT),
    CMD_SignHash = (1 << REQ_SHIFT),
  };
  struct __PACKED Request_ProvisionKey {
    static constexpr uint32_t num_handles = 0U;
    void send_handles(::trusty::aidl::Handle*&) {
    }
    void recv_handles(::trusty::aidl::Handle*&) {
    }
  };
  struct __PACKED Request_SignHash {
    static constexpr uint32_t num_handles = 0U;
    void send_handles(::trusty::aidl::Handle*&) {
    }
    void recv_handles(::trusty::aidl::Handle*&) {
    }
  };
  virtual void destroy() {}
};
}  // namespace aidl

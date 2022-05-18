#include <cassert>
#include <BpCastAuth.h>
namespace aidl {
int BpCastAuth::ProvisionKey(const ::trusty::aidl::Payload& req_payload) {
  ::trusty::aidl::RequestHeader req_hdr = {.cmd = CMD_ProvisionKey,};
  Request_ProvisionKey req = {
  };
  constexpr uint32_t req_num_handles = ::trusty::aidl::HandleOps<Request_ProvisionKey>::num_handles;
  ::trusty::aidl::Handle req_handles[req_num_handles];
  ::trusty::aidl::Handle* hptr = req_handles;
  req.send_handles(hptr);
  assert(hptr == &req_handles[req_num_handles]);
  int rc = ::trusty::aidl::ipc::send(mChan.get(), &req_hdr, sizeof(req_hdr), &req, sizeof(req), req_payload.data(), req_payload.size(), req_handles, req_num_handles);
  if (rc < 0) { return rc; }
  if (static_cast<size_t>(rc) != sizeof(req_hdr) + sizeof(req) + static_cast<size_t>(req_payload.size())) { return ::android::IO_ERROR; }
#ifdef __TRUSTY__
  uevent_t event = UEVENT_INITIAL_VALUE(event);
  rc = wait(mChan.get(), &event, INFINITE_TIME);
#endif
  if (rc != ::android::OK) { return rc; }
#ifdef __TRUSTY__
  if (!(event.event & IPC_HANDLE_POLL_MSG)) { return ::android::IO_ERROR; }
#endif
  ::trusty::aidl::ResponseHeader resp_hdr;
  rc = ::trusty::aidl::ipc::recv(mChan.get(), sizeof(resp_hdr), &resp_hdr, sizeof(resp_hdr), nullptr, 0);
  if (rc < 0) { return rc; }
  if (static_cast<size_t>(rc) < sizeof(resp_hdr)) { return ::android::NOT_ENOUGH_DATA; }
  if (resp_hdr.cmd != (CMD_ProvisionKey | RESP_BIT)) { return ::android::IO_ERROR; }
  if (resp_hdr.rc != ::android::OK) {
    if (static_cast<size_t>(rc) != sizeof(resp_hdr)) { return ::android::IO_ERROR; }
    return resp_hdr.rc;
  }
  if (static_cast<size_t>(rc) != sizeof(resp_hdr)) { return ::android::IO_ERROR; }
  return ::android::OK;
}
int BpCastAuth::SignHash(const ::trusty::aidl::Payload& req_payload, ::trusty::aidl::Payload* resp_payload) {
  ::trusty::aidl::RequestHeader req_hdr = {.cmd = CMD_SignHash,.resp_payload_size = resp_payload->size(),};
  Request_SignHash req = {
  };
  constexpr uint32_t req_num_handles = ::trusty::aidl::HandleOps<Request_SignHash>::num_handles;
  ::trusty::aidl::Handle req_handles[req_num_handles];
  ::trusty::aidl::Handle* hptr = req_handles;
  req.send_handles(hptr);
  assert(hptr == &req_handles[req_num_handles]);
  int rc = ::trusty::aidl::ipc::send(mChan.get(), &req_hdr, sizeof(req_hdr), &req, sizeof(req), req_payload.data(), req_payload.size(), req_handles, req_num_handles);
  if (rc < 0) { return rc; }
  if (static_cast<size_t>(rc) != sizeof(req_hdr) + sizeof(req) + static_cast<size_t>(req_payload.size())) { return ::android::IO_ERROR; }
#ifdef __TRUSTY__
  uevent_t event = UEVENT_INITIAL_VALUE(event);
  rc = wait(mChan.get(), &event, INFINITE_TIME);
#endif
  if (rc != ::android::OK) { return rc; }
#ifdef __TRUSTY__
  if (!(event.event & IPC_HANDLE_POLL_MSG)) { return ::android::IO_ERROR; }
#endif
  ::trusty::aidl::ResponseHeader resp_hdr;
  rc = ::trusty::aidl::ipc::recv(mChan.get(), sizeof(resp_hdr), &resp_hdr, sizeof(resp_hdr), resp_payload->data(), resp_payload->size(), nullptr, 0);
  if (rc < 0) { return rc; }
  if (static_cast<size_t>(rc) < sizeof(resp_hdr)) { return ::android::NOT_ENOUGH_DATA; }
  if (resp_hdr.cmd != (CMD_SignHash | RESP_BIT)) { return ::android::IO_ERROR; }
  if (resp_hdr.rc != ::android::OK) {
    if (static_cast<size_t>(rc) != sizeof(resp_hdr)) { return ::android::IO_ERROR; }
    return resp_hdr.rc;
  }
  if (static_cast<size_t>(rc) != sizeof(resp_hdr) + static_cast<size_t>(resp_hdr.resp_payload_size)) { return ::android::IO_ERROR; }
  resp_payload->resize(resp_hdr.resp_payload_size);
  return ::android::OK;
}
int BpCastAuth::connect(std::optional<BpCastAuth>& out, const char* port, uint32_t flags) {
  ::android::base::unique_fd fd;
  int rc = ::trusty::aidl::ipc::connect(port, flags, fd);
  if (rc != ::android::OK) { return rc; }
  out = BpCastAuth(std::move(fd));
  return ::android::OK;
}
}  // namespace aidl

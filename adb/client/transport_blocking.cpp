#define TRACE_TAG TRANSPORT

#include "sysdeps.h"

#include <mutex>

#include <android-base/thread_annotations.h>

#include <adb/crypto/rsa_2048_key.h>
#include <adb/crypto/x509_generator.h>
#include <adb/tls/tls_connection.h>

#include "adb_auth.h"
#include "adb_io.h"
#include "client/transport_blocking.h"

using namespace adb::crypto;
using namespace adb::tls;
using android::base::ScopedLockAssertion;

using TlsError = TlsConnection::TlsError;

BlockingConnectionAdapter::BlockingConnectionAdapter(std::unique_ptr<BlockingConnection> connection)
    : underlying_(std::move(connection)) {}

BlockingConnectionAdapter::~BlockingConnectionAdapter() {
    LOG(INFO) << "BlockingConnectionAdapter(" << this->transport_name_ << "): destructing";
    Stop();
}

void BlockingConnectionAdapter::Start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (started_) {
        LOG(FATAL) << "BlockingConnectionAdapter(" << this->transport_name_
                   << "): started multiple times";
    }

    StartReadThread();

    write_thread_ = std::thread([this]() {
        LOG(INFO) << this->transport_name_ << ": write thread spawning";
        while (true) {
            std::unique_lock<std::mutex> lock(mutex_);
            ScopedLockAssertion assume_locked(mutex_);
            cv_.wait(lock, [this]() REQUIRES(mutex_) {
                return this->stopped_ || !this->write_queue_.empty();
            });

            if (this->stopped_) {
                return;
            }

            std::unique_ptr<apacket> packet = std::move(this->write_queue_.front());
            this->write_queue_.pop_front();
            lock.unlock();

            if (!this->underlying_->Write(packet.get())) {
                break;
            }
        }
        std::call_once(this->error_flag_,
                       [this]() { this->error_callback_(this, "write failed"); });
    });

    started_ = true;
}

void BlockingConnectionAdapter::StartReadThread() {
    read_thread_ = std::thread([this]() {
        LOG(INFO) << this->transport_name_ << ": read thread spawning";
        while (true) {
            auto packet = std::make_unique<apacket>();
            if (!underlying_->Read(packet.get())) {
                PLOG(INFO) << this->transport_name_ << ": read failed";
                break;
            }

            bool got_stls_cmd = false;
            if (packet->msg.command == A_STLS) {
                got_stls_cmd = true;
            }

            read_callback_(this, std::move(packet));

            // If we received the STLS packet, we are about to perform the TLS
            // handshake. So this read thread must stop and resume after the
            // handshake completes otherwise this will interfere in the process.
            if (got_stls_cmd) {
                LOG(INFO) << this->transport_name_
                          << ": Received STLS packet. Stopping read thread.";
                return;
            }
        }
        std::call_once(this->error_flag_, [this]() { this->error_callback_(this, "read failed"); });
    });
}

bool BlockingConnectionAdapter::DoTlsHandshake(RSA* key, std::string* auth_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (read_thread_.joinable()) {
        read_thread_.join();
    }
    bool success = this->underlying_->DoTlsHandshake(key, auth_key);
    StartReadThread();
    return success;
}

void BlockingConnectionAdapter::Reset() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!started_) {
            LOG(INFO) << "BlockingConnectionAdapter(" << this->transport_name_ << "): not started";
            return;
        }

        if (stopped_) {
            LOG(INFO) << "BlockingConnectionAdapter(" << this->transport_name_
                      << "): already stopped";
            return;
        }
    }

    LOG(INFO) << "BlockingConnectionAdapter(" << this->transport_name_ << "): resetting";
    this->underlying_->Reset();
    Stop();
}

void BlockingConnectionAdapter::Stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!started_) {
            LOG(INFO) << "BlockingConnectionAdapter(" << this->transport_name_ << "): not started";
            return;
        }

        if (stopped_) {
            LOG(INFO) << "BlockingConnectionAdapter(" << this->transport_name_
                      << "): already stopped";
            return;
        }

        stopped_ = true;
    }

    LOG(INFO) << "BlockingConnectionAdapter(" << this->transport_name_ << "): stopping";

    this->underlying_->Close();
    this->cv_.notify_one();

    // Move the threads out into locals with the lock taken, and then unlock to let them exit.
    std::thread read_thread;
    std::thread write_thread;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        read_thread = std::move(read_thread_);
        write_thread = std::move(write_thread_);
    }

    read_thread.join();
    write_thread.join();

    LOG(INFO) << "BlockingConnectionAdapter(" << this->transport_name_ << "): stopped";
    std::call_once(this->error_flag_, [this]() { this->error_callback_(this, "requested stop"); });
}

bool BlockingConnectionAdapter::Write(std::unique_ptr<apacket> packet) {
    {
        std::lock_guard<std::mutex> lock(this->mutex_);
        write_queue_.emplace_back(std::move(packet));
    }

    cv_.notify_one();
    return true;
}

FdConnection::FdConnection(unique_fd fd) : fd_(std::move(fd)) {}

FdConnection::~FdConnection() {}

bool FdConnection::DispatchRead(void* buf, size_t len) {
    if (tls_ != nullptr) {
        // The TlsConnection doesn't allow 0 byte reads
        if (len == 0) {
            return true;
        }
        return tls_->ReadFully(buf, len);
    }

    return ReadFdExactly(fd_.get(), buf, len);
}

bool FdConnection::DispatchWrite(void* buf, size_t len) {
    if (tls_ != nullptr) {
        // The TlsConnection doesn't allow 0 byte writes
        if (len == 0) {
            return true;
        }
        return tls_->WriteFully(std::string_view(reinterpret_cast<const char*>(buf), len));
    }

    return WriteFdExactly(fd_.get(), buf, len);
}

bool FdConnection::Read(apacket* packet) {
    if (!DispatchRead(&packet->msg, sizeof(amessage))) {
        D("remote local: read terminated (message)");
        return false;
    }

    if (packet->msg.data_length > MAX_PAYLOAD) {
        D("remote local: read overflow (data length = %" PRIu32 ")", packet->msg.data_length);
        return false;
    }

    packet->payload.resize(packet->msg.data_length);

    if (!DispatchRead(&packet->payload[0], packet->payload.size())) {
        D("remote local: terminated (data)");
        return false;
    }

    return true;
}

bool FdConnection::Write(apacket* packet) {
    if (!DispatchWrite(&packet->msg, sizeof(packet->msg))) {
        D("remote local: write terminated");
        return false;
    }

    if (packet->msg.data_length) {
        if (!DispatchWrite(&packet->payload[0], packet->msg.data_length)) {
            D("remote local: write terminated");
            return false;
        }
    }

    return true;
}

bool FdConnection::DoTlsHandshake(RSA* key, std::string* auth_key) {
    bssl::UniquePtr<EVP_PKEY> evp_pkey(EVP_PKEY_new());
    if (!EVP_PKEY_set1_RSA(evp_pkey.get(), key)) {
        LOG(ERROR) << "EVP_PKEY_set1_RSA failed";
        return false;
    }
    auto x509 = GenerateX509Certificate(evp_pkey.get());
    auto x509_str = X509ToPEMString(x509.get());
    auto evp_str = Key::ToPEMString(evp_pkey.get());

    int osh = cast_handle_to_int(adb_get_os_handle(fd_));
#if ADB_HOST
    tls_ = TlsConnection::Create(TlsConnection::Role::Client, x509_str, evp_str, osh);
#else
    tls_ = TlsConnection::Create(TlsConnection::Role::Server, x509_str, evp_str, osh);
#endif
    CHECK(tls_);
#if ADB_HOST
    // TLS 1.3 gives the client no message if the server rejected the
    // certificate. This will enable a check in the tls connection to check
    // whether the client certificate got rejected. Note that this assumes
    // that, on handshake success, the server speaks first.
    tls_->EnableClientPostHandshakeCheck(true);
    // Add callback to set the certificate when server issues the
    // CertificateRequest.
    tls_->SetCertificateCallback(adb_tls_set_certificate);
    // Allow any server certificate
    tls_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 1; });
#else
    // Add callback to check certificate against a list of known public keys
    tls_->SetCertVerifyCallback(
            [auth_key](X509_STORE_CTX* ctx) { return adbd_tls_verify_cert(ctx, auth_key); });
    // Add the list of allowed client CA issuers
    auto ca_list = adbd_tls_client_ca_list();
    tls_->SetClientCAList(ca_list.get());
#endif

    auto err = tls_->DoHandshake();
    if (err == TlsError::Success) {
        return true;
    }

    tls_.reset();
    return false;
}

void FdConnection::Close() {
    adb_shutdown(fd_.get());
    fd_.reset();
}

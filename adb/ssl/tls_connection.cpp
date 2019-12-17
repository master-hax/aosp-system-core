/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "adb/ssl/tls_connection.h"

#include <algorithm>
#include <vector>

#include <android-base/logging.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace adb {
namespace ssl {

namespace {

static constexpr char kExportedKeyLabel[] = "adb-label";

class TlsConnectionImpl : public TlsConnection {
  public:
    explicit TlsConnectionImpl(Role role, std::string_view cert, std::string_view priv_key);
    ~TlsConnectionImpl() override;

    void EnableCertificateVerification(bool enable) override;
    bool AddTrustedCertificate(std::string_view cert) override;
    void SetCertVerifyCallback(CertVerifyCb cb, void* opaque) override;
    std::vector<uint8_t> ExportKeyingMaterial(size_t length) override;
    bool DoHandshake(int fd) override;
    std::vector<uint8_t> ReadFully(size_t size) override;
    bool ReadFully(void* buf, size_t size) override;
    bool WriteFully(std::string_view data) override;

  private:
    static bssl::UniquePtr<EVP_PKEY> EvpPkeyFromPEM(std::string_view pem);
    static bssl::UniquePtr<CRYPTO_BUFFER> BufferFromPEM(std::string_view pem);
    static bssl::UniquePtr<X509> X509FromBuffer(bssl::UniquePtr<CRYPTO_BUFFER> buffer);
    static const char* SSLErrorString();
    void Invalidate();

    Role role_;
    bssl::UniquePtr<EVP_PKEY> priv_key_;
    bssl::UniquePtr<CRYPTO_BUFFER> cert_;

    bssl::UniquePtr<SSL_CTX> ssl_ctx_;
    bssl::UniquePtr<SSL> ssl_;
    std::vector<bssl::UniquePtr<X509>> known_certificates_;
    bool enable_cert_verification_ = true;

    CertVerifyCb cert_verify_cb_ = [](X509_STORE_CTX*, void*) { return 1; };
    void* cert_verify_opaque_ = nullptr;
};  // TlsConnectionImpl

TlsConnectionImpl::TlsConnectionImpl(Role role, std::string_view cert, std::string_view priv_key)
    : role_(role) {
    CHECK(!cert.empty() && !priv_key.empty());
    LOG(INFO) << "Initializing adbwifi TlsConnection";
    cert_ = BufferFromPEM(cert);
    priv_key_ = EvpPkeyFromPEM(priv_key);
}

TlsConnectionImpl::~TlsConnectionImpl() {
    // shutdown the SSL connection
    if (ssl_ != nullptr) {
        SSL_shutdown(ssl_.get());
    }
}

// static
const char* TlsConnectionImpl::SSLErrorString() {
    auto sslerr = ERR_get_error();
    return ERR_reason_error_string(sslerr);
}

// static
bssl::UniquePtr<EVP_PKEY> TlsConnectionImpl::EvpPkeyFromPEM(std::string_view pem) {
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem.data(), pem.size()));
    return bssl::UniquePtr<EVP_PKEY>(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
}

// static
bssl::UniquePtr<CRYPTO_BUFFER> TlsConnectionImpl::BufferFromPEM(std::string_view pem) {
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem.data(), pem.size()));
    char* name = nullptr;
    char* header = nullptr;
    uint8_t* data = nullptr;
    long data_len = 0;

    if (!PEM_read_bio(bio.get(), &name, &header, &data, &data_len)) {
        LOG(ERROR) << "Failed to read certificate";
        return nullptr;
    }
    OPENSSL_free(name);
    OPENSSL_free(header);

    auto ret = bssl::UniquePtr<CRYPTO_BUFFER>(CRYPTO_BUFFER_new(data, data_len, nullptr));
    OPENSSL_free(data);
    return ret;
}

// static
bssl::UniquePtr<X509> TlsConnectionImpl::X509FromBuffer(bssl::UniquePtr<CRYPTO_BUFFER> buffer) {
    if (!buffer) {
        return nullptr;
    }
    return bssl::UniquePtr<X509>(X509_parse_from_buffer(buffer.get()));
}

void TlsConnectionImpl::EnableCertificateVerification(bool enable) {
    enable_cert_verification_ = enable;
}

bool TlsConnectionImpl::AddTrustedCertificate(std::string_view cert) {
    // Create X509 buffer from the certificate string
    auto buf = X509FromBuffer(BufferFromPEM(cert));
    if (buf == nullptr) {
        LOG(ERROR) << "Failed to create a X509 buffer for the certificate.";
        return false;
    }
    known_certificates_.push_back(std::move(buf));
    return true;
}

void TlsConnectionImpl::SetCertVerifyCallback(CertVerifyCb cb, void* opaque) {
    cert_verify_cb_ = cb;
    cert_verify_opaque_ = opaque;
}

std::vector<uint8_t> TlsConnectionImpl::ExportKeyingMaterial(size_t length) {
    if (ssl_.get() == nullptr) {
        return {};
    }

    std::vector<uint8_t> out(length);
    if (SSL_export_keying_material(ssl_.get(), out.data(), out.size(), kExportedKeyLabel,
                                   sizeof(kExportedKeyLabel), nullptr, 0, false) == 0) {
        return {};
    }
    return out;
}

bool TlsConnectionImpl::DoHandshake(int fd) {
    int err = -1;
    LOG(INFO) << "Starting adbwifi tls handshake";
    ssl_ctx_.reset(SSL_CTX_new(TLS_method()));
    // TODO: Remove set_max_proto_version() once external/boringssl is updated
    // past
    // https://boringssl.googlesource.com/boringssl/+/58d56f4c59969a23e5f52014e2651c76fea2f877
    if (ssl_ctx_.get() == nullptr ||
        !SSL_CTX_set_min_proto_version(ssl_ctx_.get(), TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(ssl_ctx_.get(), TLS1_3_VERSION)) {
        LOG(ERROR) << "Failed to create SSL context";
        return false;
    }

    if (enable_cert_verification_) {
        // Register every certificate in our keystore. This will restrict
        // connnections to only these known certificates.
        for (auto const& cert : known_certificates_) {
            if (X509_STORE_add_cert(SSL_CTX_get_cert_store(ssl_ctx_.get()), cert.get()) == 0) {
                LOG(ERROR) << "Unable to add certificates into the X509_STORE";
                return false;
            }
        }
    } else {
        // Custom certificate verification
        SSL_CTX_set_cert_verify_callback(ssl_ctx_.get(), cert_verify_cb_, cert_verify_opaque_);
    }

    // Register our certificate and private key.
    std::vector<CRYPTO_BUFFER*> cert_chain = {
            cert_.get(),
    };
    if (!(err = SSL_CTX_set_chain_and_key(ssl_ctx_.get(), cert_chain.data(), cert_chain.size(),
                                          priv_key_.get(), nullptr))) {
        LOG(ERROR) << "Unable to register the certificate chain file and private key ["
                   << SSLErrorString() << "]";
        Invalidate();
        return false;
    }

    SSL_CTX_set_verify(ssl_ctx_.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);

    // Okay! Let's try to do the handshake!
    ssl_.reset(SSL_new(ssl_ctx_.get()));
    if (!SSL_set_fd(ssl_.get(), fd)) {
        LOG(ERROR) << "SSL_set_fd failed. [" << SSLErrorString() << "]";
        return false;
    }
    switch (role_) {
        case Role::Server:
            err = SSL_accept(ssl_.get());
            break;
        case Role::Client:
            err = SSL_connect(ssl_.get());
            break;
    }
    if (err != 1) {
        LOG(ERROR) << "Handshake failed in SSL_accept/SSL_connect [" << SSLErrorString() << "]";
        Invalidate();
        return false;
    }

    LOG(INFO) << "Handshake succeeded.";
    return true;
}

void TlsConnectionImpl::Invalidate() {
    ssl_.reset();
    ssl_ctx_.reset();
}

std::vector<uint8_t> TlsConnectionImpl::ReadFully(size_t size) {
    CHECK_GT(size, 0U);
    if (!ssl_) {
        LOG(ERROR) << "Tried to read on a null SSL connection";
        return {};
    }

    std::vector<uint8_t> buf(size);
    size_t offset = 0;
    while (size > 0) {
        int bytes_read = SSL_read(ssl_.get(), buf.data() + offset, size);
        if (bytes_read <= 0) {
            LOG(WARNING) << "SSL_read failed [" << SSLErrorString() << "]";
            return {};
        }
        size -= bytes_read;
        offset += bytes_read;
    }
    return buf;
}

bool TlsConnectionImpl::ReadFully(void* buf, size_t size) {
    CHECK_GT(size, 0U);
    if (!ssl_) {
        LOG(ERROR) << "Tried to read on a null SSL connection";
        return false;
    }

    size_t offset = 0;
    uint8_t* p8 = reinterpret_cast<uint8_t*>(buf);
    while (size > 0) {
        int bytes_read = SSL_read(ssl_.get(), p8 + offset, size);
        if (bytes_read <= 0) {
            LOG(WARNING) << "SSL_read failed [" << SSLErrorString() << "]";
            return false;
        }
        size -= bytes_read;
        offset += bytes_read;
    }
    return true;
}

bool TlsConnectionImpl::WriteFully(std::string_view data) {
    CHECK(!data.empty());
    if (!ssl_) {
        LOG(ERROR) << "Tried to read on a null SSL connection";
        return false;
    }

    while (!data.empty()) {
        int bytes_out = SSL_write(
                ssl_.get(), data.data(),
                std::min(static_cast<uint64_t>(INT_MAX), static_cast<uint64_t>(data.size())));
        if (bytes_out <= 0) {
            LOG(WARNING) << "SSL_write failed [" << SSLErrorString() << "]";
            return false;
        }
        data = data.substr(bytes_out);
    }
    return true;
}
}  // namespace

// static
std::unique_ptr<TlsConnection> TlsConnection::Create(TlsConnection::Role role,
                                                     std::string_view cert,
                                                     std::string_view priv_key) {
    CHECK(!cert.empty());
    CHECK(!priv_key.empty());

    return std::unique_ptr<TlsConnection>(new TlsConnectionImpl(role, cert, priv_key));
}

}  // namespace ssl
}  // namespace adb

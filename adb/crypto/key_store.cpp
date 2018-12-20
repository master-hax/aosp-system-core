/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "key_store.h"

#include <android-base/logging.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "adb_utils.h"
#include "crypto/ec_key.h"
#include "crypto/identifiers.h"
#include "sysdeps.h"

static constexpr uint32_t kKeyStoreVersion = 1;

static const char kKeyStoreName[] = "adb_keystore";
static const char kPrivateKeyName[] = "adb_system_key.pem";
static const char kPublicKeyName[] = "adb_system_cert.pem";

static const char kBasicConstraints[] = "critical,CA:TRUE";
static const char kKeyUsage[] = "critical,keyCertSign,cRLSign";
static const char kSubjectKeyIdentifier[] = "hash";

static constexpr int kCurveName = NID_X9_62_prime256v1;
static constexpr int kCertLifetimeSeconds = 10 * 365 * 24 * 60 * 60;

#if ADB_HOST
static std::string getKeyStorePath() {
    return adb_get_android_dir_path() + OS_PATH_SEPARATOR + kKeyStoreName;
}
static std::string getSysPrivKeyPath() {
    return adb_get_android_dir_path() + OS_PATH_SEPARATOR + kPrivateKeyName;
}
static std::string getSysPubKeyPath() {
    return adb_get_android_dir_path() + OS_PATH_SEPARATOR + kPublicKeyName;
}
#else
static const char kKeyLocation[] = "/data/misc/adb/";

static std::string getKeyStorePath() {
    return std::string(kKeyLocation) + std::string(kKeyStoreName);
}
static std::string getSysPrivKeyPath() {
    return std::string(kKeyLocation) + std::string(kPrivateKeyName);
}
static std::string getSysPubKeyPath() {
    return std::string(kKeyLocation) + std::string(kPublicKeyName);
}

#include <grp.h>
static void listDir() {
    std::vector<gid_t> gids(4096);
    gids[0] = getgid();
    int numGroups = getgroups(gids.size() - 1, &gids[1]);
    if (numGroups >= 0) {
        gids.resize(numGroups + 1);
        std::string groups;
        for (size_t i = 0; i < gids.size(); ++i) {
            struct group* grp = getgrgid(gids[i]);
            if (grp == nullptr) {
                continue;
            }
            if (!groups.empty()) {
                groups += ", ";
            }
            groups += grp->gr_name;
        }
        LOG(ERROR) << "adb is a member of the following groups ["
                   << groups << "]";
    }

    DIR* d = opendir(kKeyLocation);
    if (!d) {
        LOG(ERROR) << "Failed to open dir " << kKeyLocation << ": " << strerror(errno);
        return;
    }

    struct dirent* dir = nullptr;
    LOG(ERROR) << "Dir '" << kKeyLocation << "' contains the following files:";
    while ((dir = readdir(d))) {
        LOG(ERROR) << dir->d_name;
    }
    closedir(d);
}
#endif


static std::string sslErrorStr() {
    bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
    ERR_print_errors(bio.get());
    char *buf = nullptr;
    size_t len = BIO_get_mem_data(bio.get(), &buf);
    if (len > 0 && buf) {
        return std::string(buf);
    }
    return "[no error]";
}

// A helper class that opens a file and unless the file is explicitly closed it
// will be deleted in the destructor of this class.
class SelfDestructingFile {
public:
    SelfDestructingFile(const char* path, const char* mode)
        : file_(fopen(path, mode)), path_(path) {
    }
    ~SelfDestructingFile() {
        if (file_) {
            fclose(file_);
            adb_unlink(path_.c_str());
        }
    }

    FILE* get() { return file_; }

    void closeAndDisarm() {
        fclose(file_);
        file_ = nullptr;
    }

private:
    FILE* file_;
    std::string path_;
};

bool KeyStore::init() {
    LOG(ERROR) << "Checking unique device id";
#if !ADB_HOST
    listDir();
#endif
    if (get_unique_device_id().empty()) {
        return false;
    }
    if (!readSystemCertificate()) {
        if (!generateSystemCertificate()) {
            return false;
        }
        // Read the certificate we just generated again, they were only stored
        // on disk.
        if (!readSystemCertificate()) {
            return false;
        }
    }
    return readPublicKeys();
}

Key* KeyStore::getSystemPublicKey(KeyType type) {
    if (public_cert_ && public_cert_->type() == type) {
        return public_cert_.get();
    }
    return nullptr;
}

bool KeyStore::storePublicKey(const std::string& identifier,
                              const std::string& name,
                              KeyType type,
                              const std::string& key) {
    std::unique_ptr<Key> keyPtr = createKey(type, name, key.c_str());
    if (!keyPtr) {
        LOG(ERROR) << "Unable to store public key";
        return false;
    }
    keys_[identifier] = std::move(keyPtr);
    if (!writePublicKeys()) {
        LOG(ERROR) << "Unable to write public key store";
        keys_.erase(identifier);
        return false;
    }
    return true;

}

bool KeyStore::getPublicKey(const std::string& identifier,
                            std::string* name,
                            KeyType* type,
                            std::string* key) {
    auto it = keys_.find(identifier);
    if (it == keys_.end()) {
        return false;
    }
    *type = it->second->type();
    *name = it->second->name();
    *key = it->second->c_str();
    return true;
}

std::pair<std::string, const Key*> KeyStore::operator[](const size_t idx) const {
    auto it = keys_.begin();
    std::advance(it, idx);
    return std::pair<std::string, const Key*>(it->first, it->second.get());
}

static bool add_ext(X509* cert, int nid, const char* value) {
    size_t len = strlen(value) + 1;
    std::vector<char> mutableValue(value, value + len);
    X509V3_CTX context;

    X509V3_set_ctx_nodb(&context);

    X509V3_set_ctx(&context, cert, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ex = X509V3_EXT_nconf_nid(nullptr, &context, nid,
                                              mutableValue.data());
    if (!ex) {
        return false;
    }

    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return true;
}

bool KeyStore::generateSystemCertificate(KeyType type) {
    LOG(ERROR) << "Generating system public key pair";
    bssl::UniquePtr<EVP_PKEY> evpKey(EVP_PKEY_new());
    if (!evpKey) {
        LOG(ERROR) << "Failed to create private/public key container";
        return false;
    }

    bssl::UniquePtr<EC_KEY> ecKey(EC_KEY_new_by_curve_name(kCurveName));
    if (!ecKey) {
        LOG(ERROR) << "Unable to create EC key";
        return false;
    }
    EC_KEY_set_asn1_flag(ecKey.get(), OPENSSL_EC_NAMED_CURVE);
    if (!EC_KEY_generate_key(ecKey.get())) {
        LOG(ERROR) << "Unable to generate EC key";
        return false;
    }

    if (!EVP_PKEY_assign_EC_KEY(evpKey.get(), ecKey.release())) {
        LOG(ERROR) << "Unable to assign EC key";
        return false;
    }

    bssl::UniquePtr<X509> x509(X509_new());
    if (!x509) {
        LOG(ERROR) << "Unable to allocate x509 container";
        return false;
    }
    X509_set_version(x509.get(), 2);

    ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1);
    X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(x509.get()), kCertLifetimeSeconds);

    if (!X509_set_pubkey(x509.get(), evpKey.get())) {
        LOG(ERROR) << "Unable to set x509 public key";
        return false;
    }

    X509_NAME* name = X509_get_subject_name(x509.get());
    if (!name) {
        LOG(ERROR) << "Unable to get x509 subject name";
        return false;
    }
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("US"),
                               -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("Android"),
                               -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("localhost"),
                               -1, -1, 0);
    if (!X509_set_issuer_name(x509.get(), name)) {
        LOG(ERROR) << "Unable to set x509 issuer name";
        return false;
    }

    add_ext(x509.get(), NID_basic_constraints, kBasicConstraints);
    add_ext(x509.get(), NID_key_usage, kKeyUsage);
    add_ext(x509.get(), NID_subject_key_identifier, kSubjectKeyIdentifier);

    int bytes = X509_sign(x509.get(), evpKey.get(), EVP_sha256());
    if (bytes <= 0) {
        LOG(ERROR) << "Unable to sign x509 certificate";
        return false;
    }

    std::unique_ptr<FILE, decltype(&fclose)> file(nullptr, &fclose);
    file.reset(fopen(getSysPrivKeyPath().c_str(), "wb"));
    if (!file) {
        LOG(ERROR) << "Unable to open private system key file for writing: "
                   << strerror(errno);
        return false;
    }
    if (!PEM_write_PKCS8PrivateKey(file.get(), evpKey.get(), nullptr, nullptr,
                                   0, nullptr, nullptr)) {
        LOG(ERROR) << "Unable to write private system key: "
                   << strerror(errno);
        return false;
    }

    file.reset(fopen(getSysPubKeyPath().c_str(), "wb"));
    if (!file) {
        LOG(ERROR) << "Unable to open public system key file";
        return false;
    }
    if (!PEM_write_X509(file.get(), x509.get())) {
        LOG(ERROR) << "Unable to write public system key file: "
                   << strerror(errno);
        return false;
    }
    return true;
}

static bool writeRecord(FILE* file, const void* data, uint32_t length) {
    uint32_t netOrderLength = htonl(length);
    if (fwrite(&netOrderLength, sizeof(netOrderLength), 1, file) != 1) {
        return false;
    }
    if (fwrite(data, length, 1, file) != 1) {
        return false;
    }
    return true;
}

static ssize_t readRecord(FILE* file, void* data, uint32_t capacity) {
    uint32_t length = 0;
    if (fread(&length, sizeof(length), 1, file) != 1) {
        return -1;
    }
    length = ntohl(length);
    if (length > capacity) {
        return -1;
    }
    if (fread(data, length, 1, file) != 1) {
        return -1;
    }
    return length;
}

template<typename F, typename... Args>
static std::string writePemToMem(F writeFunc, Args&&... args) {
    bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        return std::string();
    }
    if (!writeFunc(bio.get(), std::forward<Args>(args)...)) {
        return std::string();
    }
    char* mem = nullptr;
    long size = BIO_get_mem_data(bio.get(), &mem);
    if (size <= 0 || mem == nullptr) {
        return std::string();
    }
    return mem;
}

bool KeyStore::readSystemCertificate() {
#if !ADB_HOST
    listDir();
#endif
    LOG(ERROR) << "Reading system certificate";
    std::unique_ptr<FILE, decltype(&fclose)> file(nullptr, &fclose);
    file.reset(fopen(getSysPrivKeyPath().c_str(), "rb"));
    if (!file) {
        LOG(ERROR) << "Unable to open system private key: " << strerror(errno);
        return false;
    }

    evp_pkey_.reset(PEM_read_PrivateKey(file.get(), nullptr, nullptr, nullptr));
    if (!evp_pkey_) {
        LOG(ERROR) << "Unable to read system private key: "
                   << sslErrorStr().c_str();
        return false;
    }

    file.reset(fopen(getSysPubKeyPath().c_str(), "rb"));
    if (!file) {
        LOG(ERROR) << "Unable to open system public key";
        return false;
    }
    x509_.reset(PEM_read_X509(file.get(), nullptr, nullptr, nullptr));
    if (!x509_) {
        LOG(ERROR) << "Unable to read public system key";
        return false;
    }
    std::string certStr = writePemToMem(PEM_write_bio_X509, x509_.get());
    if (certStr.empty()) {
        LOG(ERROR) << "Unable to write certificate to string";
        return false;
    }
    public_cert_.reset(new EllipticCurveKey("systemCert", certStr.c_str()));

    std::string privateKeyStr = writePemToMem(PEM_write_bio_PrivateKey,
                                              evp_pkey_.get(),
                                              nullptr, nullptr, 0,
                                              nullptr, nullptr);
    if (certStr.empty()) {
        LOG(ERROR) << "Unable to write private key to string";
        return false;
    }
    private_key_.reset(new EllipticCurveKey("systemPK", privateKeyStr.c_str()));

    return true;
}

bool KeyStore::writeSystemCertificate() {
    return true;
}

bool KeyStore::readPublicKeys() {
    std::string storeName = getKeyStorePath();

    std::unique_ptr<FILE, decltype(&fclose)> file(fopen(storeName.c_str(),
                                                        "rb"), &fclose);
    if (file.get() == nullptr) {
        if (errno == ENOENT) {
            // File does not exist, this is not an error, it just means there
            // are no keys.
            return true;
        }
        return false;
    }

    uint32_t keyStoreVersion = 0;
    if (!readRecord(file.get(), &keyStoreVersion, sizeof(keyStoreVersion))) {
        LOG(ERROR) << "Unable to read keystore version: " << strerror(errno);
        return false;
    }

    keyStoreVersion = ntohl(keyStoreVersion);
    if (keyStoreVersion != kKeyStoreVersion) {
        LOG(ERROR) << "Invalid keystore version " << keyStoreVersion;
        return false;
    }

    char buffer[16384];
    while (true) {
        ssize_t bytes = readRecord(file.get(), buffer, sizeof(buffer));
        if (bytes <= 0 && feof(file.get())) {
            // This is OK, we just ran out of records
            break;
        }
        if (static_cast<size_t>(bytes) > kPublicKeyIdLength) {
            LOG(ERROR) << "Invalid key id in keystore file";
            return false;
        }
        std::string id(buffer, bytes);

        uint8_t typeValue = 0;
        KeyType type;
        bytes = readRecord(file.get(), &typeValue, sizeof(typeValue));
        if (bytes < 0 || !getKeyTypeFromValue(typeValue, &type)) {
            LOG(ERROR) << "Invalid key type in keystore file";
            return false;
        }

        bytes = readRecord(file.get(), buffer, sizeof(buffer));
        if (bytes < 0 || static_cast<size_t>(bytes) > kPublicKeyNameLength) {
            LOG(ERROR) << "Invalid key name in keystore file";
            return false;
        }
        std::string name(buffer, bytes);

        bytes = readRecord(file.get(), buffer, sizeof(buffer));
        if (bytes < 0) {
            LOG(ERROR) << "Invalid key in keystore file";
            return false;
        }

        std::string data(buffer, bytes);
        std::unique_ptr<Key> key = createKey(type, name, data.c_str());
        if (!key) {
            LOG(ERROR) << "Unable to create key from keystore data";
            return false;
        }
        keys_[id] = std::move(key);
    }
    return true;
}

bool KeyStore::writePublicKeys() {
    LOG(ERROR) << "Writing public keys";
#if !ADB_HOST
    listDir();
#endif
    std::string storeName = getKeyStorePath();
    std::string tempName = storeName + ".tmp";

    // This temp file should be deleted if this method fails so we don't leave
    // this stuff around. Using a temp file allows the previous data to remain
    // intact in this scenario.
    // TODO: This raises the question if it's safer to keep
    // the old data around or if everything should be nuked. If this operation
    // is preceeded by the removal of an untrusted key and this fails then the
    // untrusted key remains. On the other hand adding a new key and then
    // failing to write keys should probably not erase all known keys. We might
    // want to have the writes in these two scenarios behave differently.
    errno = 0;
    SelfDestructingFile file(tempName.c_str(), "wb");
    if (!file.get()) {
        LOG(ERROR) << "Failed to open keystore file '" << tempName
                   << "' for writing: " << strerror(errno);
        return false;
    }

    uint32_t keyStoreVersion = htonl(kKeyStoreVersion);
    if (!writeRecord(file.get(), &keyStoreVersion, sizeof(keyStoreVersion))) {
        LOG(ERROR) << "Failed to write keystore version to file '" << tempName
                   << "': " << strerror(errno);
        return false;
    }

    for (const auto& idKey : keys_) {
        const std::string& id = idKey.first;
        const Key* key = idKey.second.get();
        // Write the entire string plus the terminating zero as a separator
        if (!writeRecord(file.get(), id.c_str(), id.size())) {
            LOG(ERROR) << "Failed to write key id to file '" << tempName
                       << "': " << strerror(errno);
            return false;
        }
        uint8_t type = static_cast<uint8_t>(key->type());
        if (!writeRecord(file.get(), &type, sizeof(type))) {
            LOG(ERROR) << "Failed to write key type to file '" << tempName
                       << "': " << strerror(errno);
            return false;
        }

        if (!writeRecord(file.get(), key->name().c_str(), key->name().size())) {
            LOG(ERROR) << "Failed to write key name to file '" << tempName
                       << "': " << strerror(errno);
            return false;
        }
        if (!writeRecord(file.get(), key->c_str(), key->size())) {
            LOG(ERROR) << "Failed to write key to file '" << tempName << "': "
                       << strerror(errno);
            return false;
        }
    }

    // Replace the existing key store with the new one.
    std::string toBeDeleted = storeName;
    toBeDeleted += ".tbd";
    if (adb_rename(storeName.c_str(), toBeDeleted.c_str()) != 0) {
        // Don't exit here, this is not necessarily an error, the first time
        // around there is no key store.
        LOG(WARNING) << "Failed to rename old key store";
    }

    if (adb_rename(tempName.c_str(), storeName.c_str()) != 0) {
        LOG(ERROR) << "Failed to replace old key store";
        adb_rename(toBeDeleted.c_str(), storeName.c_str());
        return false;
    }

    adb_unlink(toBeDeleted.c_str());

    LOG(ERROR) << "Successfully wrote key store";
#if !ADB_HOST
    listDir();
#endif

    return true;
}


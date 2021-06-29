/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
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

#include <fuzz/keymaster_defs_builder.h>
#include <fuzz/keymaster_fuzzer.pb.h>
#include <hardware/keymaster_defs.h>
#include <keymaster/android_keymaster.h>
#include <unistd.h>

namespace fuzz = android::trusty::keymaster::fuzz;

void BuildBlob(const fuzz::Blob& proto_blob, keymaster_key_blob_t& blob) {
    if (!proto_blob.data().empty()) {
        blob.key_material = reinterpret_cast<const uint8_t*>(proto_blob.data().data());
        blob.key_material_size = proto_blob.data().length();
    }
}

bool BuildBuffer(const fuzz::Buffer& proto_buffer, keymaster::Buffer& buffer) {
    if (!proto_buffer.blob().data().empty()) {
        buffer = keymaster::Buffer(
                reinterpret_cast<const uint8_t*>(proto_buffer.blob().data().data()),
                proto_buffer.blob().data().length());
        buffer.advance_read(proto_buffer.read_pos());
        buffer.advance_write(proto_buffer.write_pos());
        return true;
    } else {
        return false;
    }
}

void BuildAuthorizationSet(const fuzz::AuthorizationSet& proto_set,
                           keymaster::AuthorizationSet& set) {
    for (auto proto_param : proto_set.elements()) {
        keymaster_key_param_t param = {};
        switch (proto_param.tagged_value_case()) {
            case fuzz::KeyParam::kBoolean: {
                // `false` is an invalid value so it'll easily trigger assertions
                param.boolean = true;
                auto bool_tag = proto_param.boolean().tag();
                param.tag = static_cast<keymaster_tag_t>(KM_BOOL | bool_tag);
                break;
            }
            case fuzz::KeyParam::kInteger: {
                param.integer = proto_param.integer().value();
                auto int_tag = proto_param.integer().tag();
                keymaster_tag_type_t tag_type = KM_UINT;
                if (proto_param.tag_repeats()) {
                    tag_type = KM_UINT_REP;
                }
                param.tag = static_cast<keymaster_tag_t>(tag_type | int_tag);
                break;
            }
            case fuzz::KeyParam::kLongInteger: {
                param.long_integer = proto_param.long_integer().value();
                auto long_tag = proto_param.long_integer().tag();
                keymaster_tag_type_t tag_type = KM_ULONG;
                if (proto_param.tag_repeats()) {
                    tag_type = KM_ULONG_REP;
                }
                param.tag = static_cast<keymaster_tag_t>(tag_type | long_tag);
                break;
            }
            case fuzz::KeyParam::kDateTime: {
                param.date_time = proto_param.date_time().value();
                auto date_tag = proto_param.date_time().tag();
                param.tag = static_cast<keymaster_tag_t>(KM_DATE | date_tag);
                break;
            }
            case fuzz::KeyParam::kBlob: {
                param.blob.data =
                        reinterpret_cast<const uint8_t*>(proto_param.blob().value().data().data());
                param.blob.data_length = proto_param.blob().value().data().length();
                auto blob_tag = proto_param.blob().tag();
                param.tag = static_cast<keymaster_tag_t>(KM_BYTES | blob_tag);
                break;
            }
            case fuzz::KeyParam::kBignum: {
                param.blob.data = reinterpret_cast<const uint8_t*>(
                        proto_param.bignum().value().data().data());
                param.blob.data_length = proto_param.bignum().value().data().length();
                auto bignum_tag = proto_param.bignum().tag();
                param.tag = static_cast<keymaster_tag_t>(KM_BIGNUM | bignum_tag);
                break;
            }
            case fuzz::KeyParam::kEnumerated: {
                auto tag_type = KM_ENUM;
                if (proto_param.tag_repeats()) {
                    tag_type = KM_ENUM_REP;
                }
                switch (proto_param.enumerated().value_case()) {
                    case fuzz::KeyParam::TaggedEnum::kPurpose: {
                        param.enumerated = proto_param.enumerated().purpose();
                        param.tag = static_cast<keymaster_tag_t>(tag_type | KM_TAG_PURPOSE);
                        break;
                    }
                    case fuzz::KeyParam::TaggedEnum::kAlgorithm: {
                        param.enumerated = proto_param.enumerated().algorithm();
                        param.tag = static_cast<keymaster_tag_t>(tag_type | KM_TAG_ALGORITHM);
                        break;
                    }
                    case fuzz::KeyParam::TaggedEnum::kBlockMode: {
                        param.enumerated = proto_param.enumerated().block_mode();
                        param.tag = static_cast<keymaster_tag_t>(tag_type | KM_TAG_BLOCK_MODE);
                        break;
                    }
                    case fuzz::KeyParam::TaggedEnum::kDigest: {
                        param.enumerated = proto_param.enumerated().digest();
                        param.tag = static_cast<keymaster_tag_t>(tag_type | KM_TAG_DIGEST);
                        break;
                    }
                    case fuzz::KeyParam::TaggedEnum::kPadding: {
                        param.enumerated = proto_param.enumerated().padding();
                        param.tag = static_cast<keymaster_tag_t>(tag_type | KM_TAG_PADDING);
                        break;
                    }
                    case fuzz::KeyParam::TaggedEnum::kKdf: {
                        param.enumerated = proto_param.enumerated().kdf();
                        param.tag = static_cast<keymaster_tag_t>(tag_type | KM_TAG_KDF);
                        break;
                    }
                    case fuzz::KeyParam::TaggedEnum::kEcCurve: {
                        param.enumerated = proto_param.enumerated().ec_curve();
                        param.tag = static_cast<keymaster_tag_t>(tag_type | KM_TAG_EC_CURVE);
                        break;
                    }
                    case fuzz::KeyParam::TaggedEnum::kKeyBlobUsageReqs: {
                        param.enumerated = proto_param.enumerated().key_blob_usage_reqs();
                        param.tag = static_cast<keymaster_tag_t>(tag_type |
                                                                 KM_TAG_BLOB_USAGE_REQUIREMENTS);
                        break;
                    }
                    case fuzz::KeyParam::TaggedEnum::kHwAuthType: {
                        param.enumerated = proto_param.enumerated().hw_auth_type();
                        param.tag = static_cast<keymaster_tag_t>(tag_type | KM_TAG_USER_AUTH_TYPE);
                        break;
                    }
                    case fuzz::KeyParam::TaggedEnum::kKeyOrigin: {
                        param.enumerated = proto_param.enumerated().key_origin();
                        param.tag = static_cast<keymaster_tag_t>(tag_type | KM_TAG_ORIGIN);
                        break;
                    }
                    case fuzz::KeyParam::TaggedEnum::kRsaOaepMgfDigest: {
                        param.enumerated = proto_param.enumerated().rsa_oaep_mgf_digest();
                        param.tag =
                                static_cast<keymaster_tag_t>(tag_type | KM_TAG_RSA_OAEP_MGF_DIGEST);
                        break;
                    }
                    default: {
                        param.tag = static_cast<keymaster_tag_t>(tag_type);
                        break;
                    }
                }
                // enums are the only AuthSet param variant with a restricted range of values so
                // using random values only makes sense here (i.e. protobuf-generated uint32 can
                // span the entire range of uint32_t values so occasionally using `random_value`
                // doesn't add anything there)
                if (proto_param.has_random_value()) {
                    param.enumerated = proto_param.random_value();
                }
                break;
            }
            default: {
                break;
            }
        }
        set.push_back(param);
    }
}

void BuildGenKeyAuthorizationSet(keymaster::AuthorizationSet& set) {
    // TODO: Add TAG_APPLICATION_ID and TAG_APPLICATION_DATA to the AuthorizationSet
    set = keymaster::AuthorizationSetBuilder()
                  .Authorization(keymaster::TAG_NO_AUTH_REQUIRED)
                  .RsaSigningKey(2048, 65537)
                  .Digest(KM_DIGEST_NONE)
                  .Padding(KM_PAD_NONE)
                  .build();
}

// Builds an AuthorizationSet specific to the BeginOperation command and appends a extra tags
// provided by the proto test case.
void BuildBeginOpAuthorizationSet(const fuzz::AuthorizationSet& proto_set,
                                  keymaster::AuthorizationSet& set) {
    // TODO: Add TAG_APPLICATION_ID and TAG_APPLICATION_DATA to the AuthorizationSet
    set = keymaster::AuthorizationSetBuilder().Digest(KM_DIGEST_NONE).Padding(KM_PAD_NONE).build();
    // TODO: Ensure that at least some begin op commands succeed when the proto_set isn't
    // used Optionally append extra tags provided by the proto test case
    BuildAuthorizationSet(proto_set, set);
}

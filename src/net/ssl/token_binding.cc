// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/token_binding.h"

#include <openssl/bytestring.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/mem.h>

#include "base/stl_util.h"
#include "crypto/scoped_openssl_types.h"
#include "net/base/net_errors.h"
#include "net/ssl/ssl_config.h"

namespace net {

namespace {

bool BuildTokenBindingID(crypto::ECPrivateKey* key, CBB* out) {
  EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(key->key());
  DCHECK(ec_key);

  CBB ec_point;
  return CBB_add_u8(out, TB_PARAM_ECDSAP256) &&
         CBB_add_u8_length_prefixed(out, &ec_point) &&
         EC_POINT_point2cbb(&ec_point, EC_KEY_get0_group(ec_key),
                            EC_KEY_get0_public_key(ec_key),
                            POINT_CONVERSION_UNCOMPRESSED, nullptr) &&
         CBB_flush(out);
}

bool ECDSA_SIGToRaw(ECDSA_SIG* ec_sig, EC_KEY* ec, std::vector<uint8_t>* out) {
  const EC_GROUP* group = EC_KEY_get0_group(ec);
  const BIGNUM* order = EC_GROUP_get0_order(group);
  size_t len = BN_num_bytes(order);
  out->resize(2 * len);
  if (!BN_bn2bin_padded(out->data(), len, ec_sig->r) ||
      !BN_bn2bin_padded(out->data() + len, len, ec_sig->s)) {
    return false;
  }
  return true;
}

ECDSA_SIG* RawToECDSA_SIG(EC_KEY* ec, base::StringPiece sig) {
  crypto::ScopedECDSA_SIG raw_sig(ECDSA_SIG_new());
  const EC_GROUP* group = EC_KEY_get0_group(ec);
  const BIGNUM* order = EC_GROUP_get0_order(group);
  size_t group_size = BN_num_bytes(order);
  if (sig.size() != group_size * 2)
    return nullptr;
  const uint8_t* sigp = reinterpret_cast<const uint8_t*>(sig.data());
  if (!BN_bin2bn(sigp, group_size, raw_sig->r) ||
      !BN_bin2bn(sigp + group_size, group_size, raw_sig->s)) {
    return nullptr;
  }
  return raw_sig.release();
}

}  // namespace

bool SignTokenBindingEkm(base::StringPiece ekm,
                         crypto::ECPrivateKey* key,
                         std::vector<uint8_t>* out) {
  const uint8_t* ekm_data = reinterpret_cast<const uint8_t*>(ekm.data());
  EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(key->key());
  if (!ec_key)
    return false;
  crypto::ScopedECDSA_SIG sig(ECDSA_do_sign(ekm_data, ekm.size(), ec_key));
  if (!sig)
    return false;
  return ECDSA_SIGToRaw(sig.get(), ec_key, out);
}

Error BuildTokenBindingMessageFromTokenBindings(
    const std::vector<base::StringPiece>& token_bindings,
    std::string* out) {
  CBB tb_message, child;
  if (!CBB_init(&tb_message, 0) ||
      !CBB_add_u16_length_prefixed(&tb_message, &child)) {
    CBB_cleanup(&tb_message);
    return ERR_FAILED;
  }
  for (const base::StringPiece& token_binding : token_bindings) {
    if (!CBB_add_bytes(&child,
                       reinterpret_cast<const uint8_t*>(token_binding.data()),
                       token_binding.size())) {
      CBB_cleanup(&tb_message);
      return ERR_FAILED;
    }
  }

  uint8_t* out_data;
  size_t out_len;
  if (!CBB_finish(&tb_message, &out_data, &out_len)) {
    CBB_cleanup(&tb_message);
    return ERR_FAILED;
  }
  out->assign(reinterpret_cast<char*>(out_data), out_len);
  OPENSSL_free(out_data);
  return OK;
}

Error BuildTokenBinding(TokenBindingType type,
                        crypto::ECPrivateKey* key,
                        const std::vector<uint8_t>& signed_ekm,
                        std::string* out) {
  uint8_t* out_data;
  size_t out_len;
  CBB token_binding;
  if (!CBB_init(&token_binding, 0) ||
      !CBB_add_u8(&token_binding, static_cast<uint8_t>(type)) ||
      !BuildTokenBindingID(key, &token_binding) ||
      !CBB_add_u16(&token_binding, signed_ekm.size()) ||
      !CBB_add_bytes(&token_binding, signed_ekm.data(), signed_ekm.size()) ||
      // 0-length extensions
      !CBB_add_u16(&token_binding, 0) ||
      !CBB_finish(&token_binding, &out_data, &out_len)) {
    CBB_cleanup(&token_binding);
    return ERR_FAILED;
  }
  out->assign(reinterpret_cast<char*>(out_data), out_len);
  OPENSSL_free(out_data);
  return OK;
}

TokenBinding::TokenBinding() {}

bool ParseTokenBindingMessage(base::StringPiece token_binding_message,
                              std::vector<TokenBinding>* token_bindings) {
  CBS tb_message, tb, ec_point, signature, extensions;
  uint8_t tb_type, tb_param;
  CBS_init(&tb_message,
           reinterpret_cast<const uint8_t*>(token_binding_message.data()),
           token_binding_message.size());
  if (!CBS_get_u16_length_prefixed(&tb_message, &tb))
    return false;
  while (CBS_len(&tb)) {
    if (!CBS_get_u8(&tb, &tb_type) || !CBS_get_u8(&tb, &tb_param) ||
        !CBS_get_u8_length_prefixed(&tb, &ec_point) ||
        !CBS_get_u16_length_prefixed(&tb, &signature) ||
        !CBS_get_u16_length_prefixed(&tb, &extensions) ||
        tb_param != TB_PARAM_ECDSAP256 ||
        (TokenBindingType(tb_type) != TokenBindingType::PROVIDED &&
         TokenBindingType(tb_type) != TokenBindingType::REFERRED)) {
      return false;
    }

    TokenBinding token_binding;
    token_binding.type = TokenBindingType(tb_type);
    token_binding.ec_point = std::string(
        reinterpret_cast<const char*>(CBS_data(&ec_point)), CBS_len(&ec_point));
    token_binding.signature =
        std::string(reinterpret_cast<const char*>(CBS_data(&signature)),
                    CBS_len(&signature));
    token_bindings->push_back(token_binding);
  }
  return true;
}

bool VerifyEKMSignature(base::StringPiece ec_point,
                        base::StringPiece signature,
                        base::StringPiece ekm) {
  crypto::ScopedEC_Key key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  EC_KEY* keyp = key.get();
  const uint8_t* ec_point_data =
      reinterpret_cast<const uint8_t*>(ec_point.data());
  if (o2i_ECPublicKey(&keyp, &ec_point_data, ec_point.size()) != key.get())
    return false;
  crypto::ScopedECDSA_SIG sig(RawToECDSA_SIG(keyp, signature));
  if (!sig)
    return false;
  return !!ECDSA_do_verify(reinterpret_cast<const uint8_t*>(ekm.data()),
                           ekm.size(), sig.get(), keyp);
}

}  // namespace net

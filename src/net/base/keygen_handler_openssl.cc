// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <openssl/bytestring.h>
#include <openssl/digest.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <stdint.h>

#include <memory>

#include "base/base64.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "crypto/auto_cbb.h"
#include "crypto/openssl_util.h"
#include "crypto/rsa_private_key.h"
#include "crypto/scoped_openssl_types.h"
#include "net/base/keygen_handler.h"
#include "net/base/openssl_private_key_store.h"

namespace net {

std::string KeygenHandler::GenKeyAndSignChallenge() {
  std::unique_ptr<crypto::RSAPrivateKey> key(
      crypto::RSAPrivateKey::Create(key_size_in_bits_));
  EVP_PKEY* pkey = key->key();

  if (stores_key_)
    OpenSSLPrivateKeyStore::StoreKeyPair(url_, pkey);

  // Serialize the following structure, from
  // https://developer.mozilla.org/en-US/docs/Web/HTML/Element/keygen.
  //
  //   PublicKeyAndChallenge ::= SEQUENCE {
  //       spki SubjectPublicKeyInfo,
  //       challenge IA5STRING
  //   }
  //
  //   SignedPublicKeyAndChallenge ::= SEQUENCE {
  //       publicKeyAndChallenge PublicKeyAndChallenge,
  //       signatureAlgorithm AlgorithmIdentifier,
  //       signature BIT STRING
  //   }
  //
  // The signature is over the PublicKeyAndChallenge.

  // TODO(davidben): If we gain another consumer, factor this code out into
  // shared logic, sharing OID definitions with the verifier, to support signing
  // other X.509-style structures.

  crypto::OpenSSLErrStackTracer tracer(FROM_HERE);

  // Serialize up to the PublicKeyAndChallenge.
  crypto::AutoCBB cbb;
  CBB spkac, public_key_and_challenge, challenge;
  if (!CBB_init(cbb.get(), 0) ||
      !CBB_add_asn1(cbb.get(), &spkac, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&spkac, &public_key_and_challenge, CBS_ASN1_SEQUENCE) ||
      !EVP_marshal_public_key(&public_key_and_challenge, pkey) ||
      !CBB_add_asn1(&public_key_and_challenge, &challenge,
                    CBS_ASN1_IA5STRING) ||
      !CBB_add_bytes(&challenge,
                     reinterpret_cast<const uint8_t*>(challenge_.data()),
                     challenge_.size()) ||
      !CBB_flush(&spkac)) {
    return std::string();
  }

  // Hash what's been written so far.
  crypto::ScopedEVP_MD_CTX ctx(EVP_MD_CTX_create());
  if (!EVP_DigestSignInit(ctx.get(), nullptr, EVP_md5(), nullptr, pkey) ||
      !EVP_DigestSignUpdate(ctx.get(), CBB_data(&spkac), CBB_len(&spkac))) {
    return std::string();
  }

  // The DER encoding of 1.2.840.113549.1.1.4, MD5 with RSA encryption.
  static const uint8_t kMd5WithRsaEncryption[] = {
      0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04,
  };

  // Write the signatureAlgorithm.
  CBB algorithm, oid, null;
  if (!CBB_add_asn1(&spkac, &algorithm, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&algorithm, &oid, CBS_ASN1_OBJECT) ||
      !CBB_add_bytes(&oid, kMd5WithRsaEncryption,
                     sizeof(kMd5WithRsaEncryption)) ||
      !CBB_add_asn1(&algorithm, &null, CBS_ASN1_NULL)) {
    return std::string();
  }

  // Compute and write the signature. Note that X.509 signatures, although
  // always byte strings for RSA, are encoded as BIT STRINGS with a multiple of
  // 8 bits.
  CBB sig_bitstring;
  uint8_t* sig;
  size_t sig_len;
  if (!CBB_add_asn1(&spkac, &sig_bitstring, CBS_ASN1_BITSTRING) ||
      !CBB_add_u8(&sig_bitstring, 0 /* no unused bits */) ||
      // Determine the maximum length of the signature.
      !EVP_DigestSignFinal(ctx.get(), nullptr, &sig_len) ||
      // Reserve |sig_len| bytes and write the signature to |spkac|.
      !CBB_reserve(&sig_bitstring, &sig, sig_len) ||
      !EVP_DigestSignFinal(ctx.get(), sig, &sig_len) ||
      !CBB_did_write(&sig_bitstring, sig_len)) {
    return std::string();
  }

  // Finally, the structure is base64-encoded.
  uint8_t* der;
  size_t der_len;
  if (!CBB_finish(cbb.get(), &der, &der_len)) {
    return std::string();
  }
  std::string result;
  base::Base64Encode(
      base::StringPiece(reinterpret_cast<const char*>(der), der_len), &result);
  OPENSSL_free(der);
  return result;
}

}  // namespace net

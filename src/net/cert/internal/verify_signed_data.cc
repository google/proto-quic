// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/verify_signed_data.h"

#include <openssl/bytestring.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "base/compiler_specific.h"
#include "base/logging.h"
#include "crypto/openssl_util.h"
#include "crypto/scoped_openssl_types.h"
#include "net/cert/internal/signature_algorithm.h"
#include "net/cert/internal/signature_policy.h"
#include "net/der/input.h"
#include "net/der/parse_values.h"
#include "net/der/parser.h"

namespace net {

namespace {

// Converts a DigestAlgorithm to an equivalent EVP_MD*.
WARN_UNUSED_RESULT bool GetDigest(DigestAlgorithm digest, const EVP_MD** out) {
  *out = nullptr;

  switch (digest) {
    case DigestAlgorithm::Sha1:
      *out = EVP_sha1();
      break;
    case DigestAlgorithm::Sha256:
      *out = EVP_sha256();
      break;
    case DigestAlgorithm::Sha384:
      *out = EVP_sha384();
      break;
    case DigestAlgorithm::Sha512:
      *out = EVP_sha512();
      break;
  }

  return *out != nullptr;
}

// Sets the RSASSA-PSS parameters on |pctx|. Returns true on success.
WARN_UNUSED_RESULT bool ApplyRsaPssOptions(const RsaPssParameters* params,
                                           EVP_PKEY_CTX* pctx) {
  // BoringSSL takes a signed int for the salt length, and interprets
  // negative values in a special manner. Make sure not to silently underflow.
  base::CheckedNumeric<int> salt_length_bytes_int(params->salt_length());
  if (!salt_length_bytes_int.IsValid())
    return false;

  const EVP_MD* mgf1_hash;
  if (!GetDigest(params->mgf1_hash(), &mgf1_hash))
    return false;

  return EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) &&
         EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, mgf1_hash) &&
         EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
                                          salt_length_bytes_int.ValueOrDie());
}

// TODO(eroman): This function is not strict enough. It accepts BER, other RSA
// OIDs, and does not check id-rsaEncryption parameters.
// See https://crbug.com/522228 and https://crbug.com/522232
WARN_UNUSED_RESULT bool ImportPkeyFromSpki(const der::Input& spki,
                                           int expected_pkey_id,
                                           crypto::ScopedEVP_PKEY* pkey) {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  CBS cbs;
  CBS_init(&cbs, spki.UnsafeData(), spki.Length());
  pkey->reset(EVP_parse_public_key(&cbs));
  if (!*pkey || CBS_len(&cbs) != 0 ||
      EVP_PKEY_id(pkey->get()) != expected_pkey_id) {
    pkey->reset();
    return false;
  }

  return true;
}

// Parses an RSA public key from SPKI to an EVP_PKEY.
//
// Returns true on success.
//
// There are two flavors of RSA public key that this function should recognize
// from RFC 5912 (however note that pk-rsaSSA-PSS is not supported in the
// current implementation).
// TODO(eroman): Support id-RSASSA-PSS and its associated parameters. See
// https://crbug.com/522232
//
//     pk-rsa PUBLIC-KEY ::= {
//      IDENTIFIER rsaEncryption
//      KEY RSAPublicKey
//      PARAMS TYPE NULL ARE absent
//      -- Private key format not in this module --
//      CERT-KEY-USAGE {digitalSignature, nonRepudiation,
//      keyEncipherment, dataEncipherment, keyCertSign, cRLSign}
//     }
//
//  ...
//
//     pk-rsaSSA-PSS PUBLIC-KEY ::= {
//         IDENTIFIER id-RSASSA-PSS
//         KEY RSAPublicKey
//         PARAMS TYPE RSASSA-PSS-params ARE optional
//          -- Private key format not in this module --
//         CERT-KEY-USAGE { nonRepudiation, digitalSignature,
//                              keyCertSign, cRLSign }
//     }
//
// Any RSA signature algorithm can accept a "pk-rsa" (rsaEncryption). However a
// "pk-rsaSSA-PSS" key is only accepted if the signature algorithm was for PSS
// mode:
//
//     sa-rsaSSA-PSS SIGNATURE-ALGORITHM ::= {
//         IDENTIFIER id-RSASSA-PSS
//         PARAMS TYPE RSASSA-PSS-params ARE required
//         HASHES { mda-sha1 | mda-sha224 | mda-sha256 | mda-sha384
//                      | mda-sha512 }
//         PUBLIC-KEYS { pk-rsa | pk-rsaSSA-PSS }
//         SMIME-CAPS { IDENTIFIED BY id-RSASSA-PSS }
//     }
//
// Moreover, if a "pk-rsaSSA-PSS" key was used and it optionally provided
// parameters for the algorithm, they must match those of the signature
// algorithm.
//
// COMPATIBILITY NOTE: RFC 5912 and RFC 3279 are in disagreement on the value
// of parameters for rsaEncryption. Whereas RFC 5912 says they must be absent,
// RFC 3279 says they must be NULL:
//
//     The rsaEncryption OID is intended to be used in the algorithm field
//     of a value of type AlgorithmIdentifier.  The parameters field MUST
//     have ASN.1 type NULL for this algorithm identifier.
//
// Following RFC 3279 in this case.
WARN_UNUSED_RESULT bool ParseRsaKeyFromSpki(const der::Input& public_key_spki,
                                            crypto::ScopedEVP_PKEY* pkey,
                                            const SignaturePolicy* policy) {
  if (!ImportPkeyFromSpki(public_key_spki, EVP_PKEY_RSA, pkey))
    return false;

  // Extract the modulus length from the key.
  crypto::ScopedRSA rsa(EVP_PKEY_get1_RSA(pkey->get()));
  if (!rsa)
    return false;
  unsigned int modulus_length_bits = BN_num_bits(rsa->n);

  return policy->IsAcceptableModulusLengthForRsa(modulus_length_bits);
}

// Does signature verification using either RSA or ECDSA.
WARN_UNUSED_RESULT bool DoVerify(const SignatureAlgorithm& algorithm,
                                 const der::Input& signed_data,
                                 const der::BitString& signature_value,
                                 EVP_PKEY* public_key) {
  DCHECK(algorithm.algorithm() == SignatureAlgorithmId::RsaPkcs1 ||
         algorithm.algorithm() == SignatureAlgorithmId::RsaPss ||
         algorithm.algorithm() == SignatureAlgorithmId::Ecdsa);

  // For the supported algorithms the signature value must be a whole
  // number of bytes.
  if (signature_value.unused_bits() != 0)
    return false;
  const der::Input& signature_value_bytes = signature_value.bytes();

  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  crypto::ScopedEVP_MD_CTX ctx(EVP_MD_CTX_create());
  EVP_PKEY_CTX* pctx = nullptr;  // Owned by |ctx|.

  const EVP_MD* digest;
  if (!GetDigest(algorithm.digest(), &digest))
    return false;

  if (!EVP_DigestVerifyInit(ctx.get(), &pctx, digest, nullptr, public_key))
    return false;

  // Set the RSASSA-PSS specific options.
  if (algorithm.algorithm() == SignatureAlgorithmId::RsaPss &&
      !ApplyRsaPssOptions(algorithm.ParamsForRsaPss(), pctx)) {
    return false;
  }

  if (!EVP_DigestVerifyUpdate(ctx.get(), signed_data.UnsafeData(),
                              signed_data.Length())) {
    return false;
  }

  return 1 == EVP_DigestVerifyFinal(ctx.get(),
                                    signature_value_bytes.UnsafeData(),
                                    signature_value_bytes.Length());
}

// Parses an EC public key from SPKI to an EVP_PKEY.
//
// Returns true on success.
//
// RFC 5912 describes all the ECDSA signature algorithms as requiring a public
// key of type "pk-ec":
//
//     pk-ec PUBLIC-KEY ::= {
//      IDENTIFIER id-ecPublicKey
//      KEY ECPoint
//      PARAMS TYPE ECParameters ARE required
//      -- Private key format not in this module --
//      CERT-KEY-USAGE { digitalSignature, nonRepudiation, keyAgreement,
//                           keyCertSign, cRLSign }
//     }
//
// Moreover RFC 5912 stipulates what curves are allowed. The ECParameters
// MUST NOT use an implicitCurve or specificCurve for PKIX:
//
//     ECParameters ::= CHOICE {
//      namedCurve      CURVE.&id({NamedCurve})
//      -- implicitCurve   NULL
//        -- implicitCurve MUST NOT be used in PKIX
//      -- specifiedCurve  SpecifiedCurve
//        -- specifiedCurve MUST NOT be used in PKIX
//        -- Details for specifiedCurve can be found in [X9.62]
//        -- Any future additions to this CHOICE should be coordinated
//        -- with ANSI X.9.
//     }
//     -- If you need to be able to decode ANSI X.9 parameter structures,
//     -- uncomment the implicitCurve and specifiedCurve above, and also
//     -- uncomment the following:
//     --(WITH COMPONENTS {namedCurve PRESENT})
//
// The namedCurves are extensible. The ones described by RFC 5912 are:
//
//     NamedCurve CURVE ::= {
//     { ID secp192r1 } | { ID sect163k1 } | { ID sect163r2 } |
//     { ID secp224r1 } | { ID sect233k1 } | { ID sect233r1 } |
//     { ID secp256r1 } | { ID sect283k1 } | { ID sect283r1 } |
//     { ID secp384r1 } | { ID sect409k1 } | { ID sect409r1 } |
//     { ID secp521r1 } | { ID sect571k1 } | { ID sect571r1 },
//     ... -- Extensible
//     }
WARN_UNUSED_RESULT bool ParseEcKeyFromSpki(const der::Input& public_key_spki,
                                           crypto::ScopedEVP_PKEY* pkey,
                                           const SignaturePolicy* policy) {
  if (!ImportPkeyFromSpki(public_key_spki, EVP_PKEY_EC, pkey))
    return false;

  // Extract the curve name.
  crypto::ScopedEC_KEY ec(EVP_PKEY_get1_EC_KEY(pkey->get()));
  if (!ec.get())
    return false;  // Unexpected.
  int curve_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec.get()));

  return policy->IsAcceptableCurveForEcdsa(curve_nid);
}

}  // namespace

bool VerifySignedData(const SignatureAlgorithm& signature_algorithm,
                      const der::Input& signed_data,
                      const der::BitString& signature_value,
                      const der::Input& public_key_spki,
                      const SignaturePolicy* policy) {
  if (!policy->IsAcceptableSignatureAlgorithm(signature_algorithm))
    return false;

  crypto::ScopedEVP_PKEY public_key;

  // Parse the SPKI to an EVP_PKEY appropriate for the signature algorithm.
  switch (signature_algorithm.algorithm()) {
    case SignatureAlgorithmId::RsaPkcs1:
    case SignatureAlgorithmId::RsaPss:
      if (!ParseRsaKeyFromSpki(public_key_spki, &public_key, policy))
        return false;
      break;
    case SignatureAlgorithmId::Ecdsa:
      if (!ParseEcKeyFromSpki(public_key_spki, &public_key, policy))
        return false;
      break;
  }

  return DoVerify(signature_algorithm, signed_data, signature_value,
                  public_key.get());
}

}  // namespace net

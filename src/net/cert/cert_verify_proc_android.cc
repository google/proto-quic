// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verify_proc_android.h"

#include <openssl/x509v3.h>

#include <string>
#include <vector>

#include "base/logging.h"
#include "base/sha1.h"
#include "base/strings/string_piece.h"
#include "crypto/sha2.h"
#include "net/android/cert_verify_result_android.h"
#include "net/android/network_library.h"
#include "net/base/net_errors.h"
#include "net/cert/asn1_util.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/x509_certificate.h"

namespace net {

namespace {

// Returns true if the certificate verification call was successful (regardless
// of its result), i.e. if |verify_result| was set. Otherwise returns false.
bool VerifyFromAndroidTrustManager(const std::vector<std::string>& cert_bytes,
                                   const std::string& hostname,
                                   CertVerifyResult* verify_result) {
  android::CertVerifyStatusAndroid status;
  std::vector<std::string> verified_chain;

  // TODO(joth): Fetch the authentication type from SSL rather than hardcode.
  android::VerifyX509CertChain(cert_bytes, "RSA", hostname,
                               &status, &verify_result->is_issued_by_known_root,
                               &verified_chain);
  switch (status) {
    case android::CERT_VERIFY_STATUS_ANDROID_FAILED:
      return false;
    case android::CERT_VERIFY_STATUS_ANDROID_OK:
      break;
    case android::CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT:
      verify_result->cert_status |= CERT_STATUS_AUTHORITY_INVALID;
      break;
    case android::CERT_VERIFY_STATUS_ANDROID_EXPIRED:
    case android::CERT_VERIFY_STATUS_ANDROID_NOT_YET_VALID:
      verify_result->cert_status |= CERT_STATUS_DATE_INVALID;
      break;
    case android::CERT_VERIFY_STATUS_ANDROID_UNABLE_TO_PARSE:
      verify_result->cert_status |= CERT_STATUS_INVALID;
      break;
    case android::CERT_VERIFY_STATUS_ANDROID_INCORRECT_KEY_USAGE:
      verify_result->cert_status |= CERT_STATUS_INVALID;
      break;
    default:
      NOTREACHED();
      verify_result->cert_status |= CERT_STATUS_INVALID;
      break;
  }

  // Save the verified chain.
  if (!verified_chain.empty()) {
    std::vector<base::StringPiece> verified_chain_pieces(verified_chain.size());
    for (size_t i = 0; i < verified_chain.size(); i++) {
      verified_chain_pieces[i] = base::StringPiece(verified_chain[i]);
    }
    scoped_refptr<X509Certificate> verified_cert =
        X509Certificate::CreateFromDERCertChain(verified_chain_pieces);
    if (verified_cert.get())
      verify_result->verified_cert = verified_cert;
  }

  // Extract the algorithm information from the certs
  X509Certificate::OSCertHandles chain;
  const X509Certificate::OSCertHandles& intermediates =
      verify_result->verified_cert->GetIntermediateCertificates();
  chain.push_back(verify_result->verified_cert->os_cert_handle());
  chain.insert(chain.end(), intermediates.begin(), intermediates.end());

  // If the chain successfully verified, ignore the trust anchor (the last
  // certificate). Otherwise, assume the chain is partial. This is not entirely
  // correct, as a full chain may have been constructed and then failed to
  // validate. However, if that is the case, the more serious error will
  // override any SHA-1 considerations.
  size_t correction_for_root =
      (status == android::CERT_VERIFY_STATUS_ANDROID_OK) ? 1 : 0;
  for (size_t i = 0; i < chain.size() - correction_for_root; ++i) {
    int sig_alg = OBJ_obj2nid(chain[i]->sig_alg->algorithm);
    if (sig_alg == NID_md2WithRSAEncryption) {
      verify_result->has_md2 = true;
    } else if (sig_alg == NID_md4WithRSAEncryption) {
      verify_result->has_md4 = true;
    } else if (sig_alg == NID_md5WithRSAEncryption ||
               sig_alg == NID_md5WithRSA) {
      verify_result->has_md5 = true;
    } else if (sig_alg == NID_sha1WithRSAEncryption ||
               sig_alg == NID_dsaWithSHA || sig_alg == NID_dsaWithSHA1 ||
               sig_alg == NID_dsaWithSHA1_2 || sig_alg == NID_sha1WithRSA ||
               sig_alg == NID_ecdsa_with_SHA1) {
      verify_result->has_sha1 = true;
      if (i == 0)
        verify_result->has_sha1_leaf = true;
    }
  }

  // Extract the public key hashes.
  for (size_t i = 0; i < verified_chain.size(); i++) {
    base::StringPiece spki_bytes;
    if (!asn1::ExtractSPKIFromDERCert(verified_chain[i], &spki_bytes))
      continue;

    HashValue sha1(HASH_VALUE_SHA1);
    base::SHA1HashBytes(reinterpret_cast<const uint8_t*>(spki_bytes.data()),
                        spki_bytes.size(), sha1.data());
    verify_result->public_key_hashes.push_back(sha1);

    HashValue sha256(HASH_VALUE_SHA256);
    crypto::SHA256HashString(spki_bytes, sha256.data(), crypto::kSHA256Length);
    verify_result->public_key_hashes.push_back(sha256);
  }

  return true;
}

bool GetChainDEREncodedBytes(X509Certificate* cert,
                             std::vector<std::string>* chain_bytes) {
  X509Certificate::OSCertHandle cert_handle = cert->os_cert_handle();
  X509Certificate::OSCertHandles cert_handles =
      cert->GetIntermediateCertificates();

  // Make sure the peer's own cert is the first in the chain, if it's not
  // already there.
  if (cert_handles.empty() || cert_handles[0] != cert_handle)
    cert_handles.insert(cert_handles.begin(), cert_handle);

  chain_bytes->reserve(cert_handles.size());
  for (X509Certificate::OSCertHandles::const_iterator it =
       cert_handles.begin(); it != cert_handles.end(); ++it) {
    std::string cert_bytes;
    if(!X509Certificate::GetDEREncoded(*it, &cert_bytes))
      return false;
    chain_bytes->push_back(cert_bytes);
  }
  return true;
}

}  // namespace

CertVerifyProcAndroid::CertVerifyProcAndroid() {}

CertVerifyProcAndroid::~CertVerifyProcAndroid() {}

bool CertVerifyProcAndroid::SupportsAdditionalTrustAnchors() const {
  return false;
}

bool CertVerifyProcAndroid::SupportsOCSPStapling() const {
  return false;
}

int CertVerifyProcAndroid::VerifyInternal(
    X509Certificate* cert,
    const std::string& hostname,
    const std::string& ocsp_response,
    int flags,
    CRLSet* crl_set,
    const CertificateList& additional_trust_anchors,
    CertVerifyResult* verify_result) {
  if (!cert->VerifyNameMatch(hostname,
                             &verify_result->common_name_fallback_used)) {
    verify_result->cert_status |= CERT_STATUS_COMMON_NAME_INVALID;
  }

  std::vector<std::string> cert_bytes;
  if (!GetChainDEREncodedBytes(cert, &cert_bytes))
    return ERR_CERT_INVALID;
  if (!VerifyFromAndroidTrustManager(cert_bytes, hostname, verify_result)) {
    NOTREACHED();
    return ERR_FAILED;
  }
  if (IsCertStatusError(verify_result->cert_status))
    return MapCertStatusToNetError(verify_result->cert_status);

  return OK;
}

}  // namespace net

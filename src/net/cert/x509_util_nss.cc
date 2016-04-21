// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_util_nss.h"

#include <cert.h>  // Must be included before certdb.h
#include <certdb.h>
#include <cryptohi.h>
#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <secder.h>
#include <secmod.h>
#include <secport.h>

#include <memory>

#include "base/debug/leak_annotations.h"
#include "base/logging.h"
#include "base/memory/singleton.h"
#include "base/pickle.h"
#include "base/strings/stringprintf.h"
#include "crypto/ec_private_key.h"
#include "crypto/nss_util.h"
#include "crypto/nss_util_internal.h"
#include "crypto/rsa_private_key.h"
#include "crypto/scoped_nss_types.h"
#include "crypto/third_party/nss/chromium-nss.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"

namespace net {

namespace {

// Creates a Certificate object that may be passed to the SignCertificate
// method to generate an X509 certificate.
// Returns NULL if an error is encountered in the certificate creation
// process.
// Caller responsible for freeing returned certificate object.
CERTCertificate* CreateCertificate(SECKEYPublicKey* public_key,
                                   const std::string& subject,
                                   uint32_t serial_number,
                                   base::Time not_valid_before,
                                   base::Time not_valid_after) {
  // Create info about public key.
  CERTSubjectPublicKeyInfo* spki =
      SECKEY_CreateSubjectPublicKeyInfo(public_key);
  if (!spki)
    return NULL;

  // Create the certificate request.
  CERTName* subject_name =
      CERT_AsciiToName(const_cast<char*>(subject.c_str()));
  CERTCertificateRequest* cert_request =
      CERT_CreateCertificateRequest(subject_name, spki, NULL);
  SECKEY_DestroySubjectPublicKeyInfo(spki);

  if (!cert_request) {
    PRErrorCode prerr = PR_GetError();
    LOG(ERROR) << "Failed to create certificate request: " << prerr;
    CERT_DestroyName(subject_name);
    return NULL;
  }

  CERTValidity* validity = CERT_CreateValidity(
      crypto::BaseTimeToPRTime(not_valid_before),
      crypto::BaseTimeToPRTime(not_valid_after));
  if (!validity) {
    PRErrorCode prerr = PR_GetError();
    LOG(ERROR) << "Failed to create certificate validity object: " << prerr;
    CERT_DestroyName(subject_name);
    CERT_DestroyCertificateRequest(cert_request);
    return NULL;
  }
  CERTCertificate* cert = CERT_CreateCertificate(serial_number, subject_name,
                                                 validity, cert_request);
  if (!cert) {
    PRErrorCode prerr = PR_GetError();
    LOG(ERROR) << "Failed to create certificate: " << prerr;
  }

  // Cleanup for resources used to generate the cert.
  CERT_DestroyName(subject_name);
  CERT_DestroyValidity(validity);
  CERT_DestroyCertificateRequest(cert_request);

  return cert;
}

SECOidTag ToSECOid(x509_util::DigestAlgorithm alg) {
  switch (alg) {
    case x509_util::DIGEST_SHA1:
      return SEC_OID_SHA1;
    case x509_util::DIGEST_SHA256:
      return SEC_OID_SHA256;
  }
  return SEC_OID_UNKNOWN;
}

// Signs a certificate object, with |key| generating a new X509Certificate
// and destroying the passed certificate object (even when NULL is returned).
// The logic of this method references SignCert() in NSS utility certutil:
// http://mxr.mozilla.org/security/ident?i=SignCert.
// Returns true on success or false if an error is encountered in the
// certificate signing process.
bool SignCertificate(
    CERTCertificate* cert,
    SECKEYPrivateKey* key,
    SECOidTag hash_algorithm) {
  // |arena| is used to encode the cert.
  PLArenaPool* arena = cert->arena;
  SECOidTag algo_id = SEC_GetSignatureAlgorithmOidTag(key->keyType,
                                                      hash_algorithm);
  if (algo_id == SEC_OID_UNKNOWN)
    return false;

  SECStatus rv = SECOID_SetAlgorithmID(arena, &cert->signature, algo_id, 0);
  if (rv != SECSuccess)
    return false;

  // Generate a cert of version 3.
  *(cert->version.data) = 2;
  cert->version.len = 1;

  SECItem der = { siBuffer, NULL, 0 };

  // Use ASN1 DER to encode the cert.
  void* encode_result = SEC_ASN1EncodeItem(
      NULL, &der, cert, SEC_ASN1_GET(CERT_CertificateTemplate));
  if (!encode_result)
    return false;

  // Allocate space to contain the signed cert.
  SECItem result = { siBuffer, NULL, 0 };

  // Sign the ASN1 encoded cert and save it to |result|.
  rv = DerSignData(arena, &result, &der, key, algo_id);
  PORT_Free(der.data);
  if (rv != SECSuccess) {
    DLOG(ERROR) << "DerSignData: " << PORT_GetError();
    return false;
  }

  // Save the signed result to the cert.
  cert->derCert = result;

  return true;
}

}  // namespace

namespace x509_util {

bool CreateSelfSignedCert(crypto::RSAPrivateKey* key,
                          DigestAlgorithm alg,
                          const std::string& subject,
                          uint32_t serial_number,
                          base::Time not_valid_before,
                          base::Time not_valid_after,
                          std::string* der_cert) {
  DCHECK(key);
  DCHECK(!strncmp(subject.c_str(), "CN=", 3U));
  CERTCertificate* cert = CreateCertificate(key->public_key(),
                                            subject,
                                            serial_number,
                                            not_valid_before,
                                            not_valid_after);
  if (!cert)
    return false;

  if (!SignCertificate(cert, key->key(), ToSECOid(alg))) {
    CERT_DestroyCertificate(cert);
    return false;
  }

  der_cert->assign(reinterpret_cast<char*>(cert->derCert.data),
                   cert->derCert.len);
  CERT_DestroyCertificate(cert);
  return true;
}

bool GetTLSServerEndPointChannelBinding(const X509Certificate& certificate,
                                        std::string* token) {
  NOTIMPLEMENTED();
  return false;
}

} // namespace x509_util

} // namespace net

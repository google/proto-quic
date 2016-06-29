// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cert.h>
#include <cryptohi.h>
#include <keyhi.h>
#include <nss.h>
#include <pk11pub.h>
#include <prtime.h>
#include <seccomon.h>
#include <secder.h>
#include <sechash.h>

#include <memory>

#include "base/logging.h"
#include "base/numerics/safe_conversions.h"
#include "base/pickle.h"
#include "base/strings/stringprintf.h"
#include "base/time/time.h"
#include "crypto/nss_util.h"
#include "crypto/scoped_nss_types.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util_nss.h"

namespace net {

void X509Certificate::Initialize() {
  x509_util::ParsePrincipal(&cert_handle_->subject, &subject_);
  x509_util::ParsePrincipal(&cert_handle_->issuer, &issuer_);

  x509_util::ParseDate(&cert_handle_->validity.notBefore, &valid_start_);
  x509_util::ParseDate(&cert_handle_->validity.notAfter, &valid_expiry_);

  serial_number_ = x509_util::ParseSerialNumber(cert_handle_);
}

// static
scoped_refptr<X509Certificate> X509Certificate::CreateFromBytesWithNickname(
    const char* data,
    size_t length,
    const char* nickname) {
  OSCertHandle cert_handle = CreateOSCertHandleFromBytesWithNickname(data,
                                                                     length,
                                                                     nickname);
  if (!cert_handle)
    return NULL;

  scoped_refptr<X509Certificate> cert =
      CreateFromHandle(cert_handle, OSCertHandles());
  FreeOSCertHandle(cert_handle);

  if (nickname)
    cert->default_nickname_ = nickname;

  return cert;
}

std::string X509Certificate::GetDefaultNickname(CertType type) const {
  if (!default_nickname_.empty())
    return default_nickname_;

  std::string result;
  if (type == USER_CERT && cert_handle_->slot) {
    // Find the private key for this certificate and see if it has a
    // nickname.  If there is a private key, and it has a nickname, then
    // return that nickname.
    SECKEYPrivateKey* private_key = PK11_FindPrivateKeyFromCert(
        cert_handle_->slot,
        cert_handle_,
        NULL);  // wincx
    if (private_key) {
      char* private_key_nickname = PK11_GetPrivateKeyNickname(private_key);
      if (private_key_nickname) {
        result = private_key_nickname;
        PORT_Free(private_key_nickname);
        SECKEY_DestroyPrivateKey(private_key);
        return result;
      }
      SECKEY_DestroyPrivateKey(private_key);
    }
  }

  switch (type) {
    case CA_CERT: {
      char* nickname = CERT_MakeCANickname(cert_handle_);
      result = nickname;
      PORT_Free(nickname);
      break;
    }
    case USER_CERT: {
      std::string subject_name = subject_.GetDisplayName();
      if (subject_name.empty()) {
        const char* email = CERT_GetFirstEmailAddress(cert_handle_);
        if (email)
          subject_name = email;
      }
      // TODO(gspencer): Internationalize this. It's wrong to assume English
      // here.
      result = base::StringPrintf("%s's %s ID", subject_name.c_str(),
                                  issuer_.GetDisplayName().c_str());
      break;
    }
    case SERVER_CERT:
      result = subject_.GetDisplayName();
      break;
    case OTHER_CERT:
    default:
      break;
  }
  return result;
}

void X509Certificate::GetSubjectAltName(
    std::vector<std::string>* dns_names,
    std::vector<std::string>* ip_addrs) const {
  x509_util::GetSubjectAltName(cert_handle_, dns_names, ip_addrs);
}

bool X509Certificate::IsIssuedByEncoded(
    const std::vector<std::string>& valid_issuers) {
  // Get certificate chain as scoped list of CERTCertificate objects.
  std::vector<CERTCertificate*> cert_chain;
  cert_chain.push_back(cert_handle_);
  for (size_t n = 0; n < intermediate_ca_certs_.size(); ++n) {
    cert_chain.push_back(intermediate_ca_certs_[n]);
  }
  // Convert encoded issuers to scoped CERTName* list.
  std::vector<CERTName*> issuers;
  crypto::ScopedPLArenaPool arena(PORT_NewArena(DER_DEFAULT_CHUNKSIZE));
  if (!x509_util::GetIssuersFromEncodedList(valid_issuers,
                                            arena.get(),
                                            &issuers)) {
    return false;
  }
  return x509_util::IsCertificateIssuedBy(cert_chain, issuers);
}

// static
bool X509Certificate::GetDEREncoded(X509Certificate::OSCertHandle cert_handle,
                                    std::string* encoded) {
  if (!cert_handle || !cert_handle->derCert.len)
    return false;
  encoded->assign(reinterpret_cast<char*>(cert_handle->derCert.data),
                  cert_handle->derCert.len);
  return true;
}

// static
bool X509Certificate::IsSameOSCert(X509Certificate::OSCertHandle a,
                                   X509Certificate::OSCertHandle b) {
  DCHECK(a && b);
  if (a == b)
    return true;
  return a->derCert.len == b->derCert.len &&
      memcmp(a->derCert.data, b->derCert.data, a->derCert.len) == 0;
}

// static
X509Certificate::OSCertHandle X509Certificate::CreateOSCertHandleFromBytes(
    const char* data,
    size_t length) {
  return CreateOSCertHandleFromBytesWithNickname(data, length, NULL);
}

// static
X509Certificate::OSCertHandle
X509Certificate::CreateOSCertHandleFromBytesWithNickname(const char* data,
                                                         size_t length,
                                                         const char* nickname) {
  crypto::EnsureNSSInit();

  if (!NSS_IsInitialized())
    return NULL;

  SECItem der_cert;
  der_cert.data = reinterpret_cast<unsigned char*>(const_cast<char*>(data));
  der_cert.len = base::checked_cast<unsigned>(length);
  der_cert.type = siDERCertBuffer;

  // Parse into a certificate structure.
  return CERT_NewTempCertificate(CERT_GetDefaultCertDB(), &der_cert,
                                 const_cast<char*>(nickname),
                                 PR_FALSE, PR_TRUE);
}

// static
X509Certificate::OSCertHandles X509Certificate::CreateOSCertHandlesFromBytes(
    const char* data,
    size_t length,
    Format format) {
  return x509_util::CreateOSCertHandlesFromBytes(data, length, format);
}

// static
X509Certificate::OSCertHandle X509Certificate::DupOSCertHandle(
    OSCertHandle cert_handle) {
  return CERT_DupCertificate(cert_handle);
}

// static
void X509Certificate::FreeOSCertHandle(OSCertHandle cert_handle) {
  CERT_DestroyCertificate(cert_handle);
}

// static
SHA256HashValue X509Certificate::CalculateFingerprint256(OSCertHandle cert) {
  SHA256HashValue sha256;
  memset(sha256.data, 0, sizeof(sha256.data));

  DCHECK(NULL != cert->derCert.data);
  DCHECK_NE(0U, cert->derCert.len);

  SECStatus rv = HASH_HashBuf(
      HASH_AlgSHA256, sha256.data, cert->derCert.data, cert->derCert.len);
  DCHECK_EQ(SECSuccess, rv);

  return sha256;
}

// static
SHA256HashValue X509Certificate::CalculateCAFingerprint256(
    const OSCertHandles& intermediates) {
  SHA256HashValue sha256;
  memset(sha256.data, 0, sizeof(sha256.data));

  HASHContext* sha256_ctx = HASH_Create(HASH_AlgSHA256);
  if (!sha256_ctx)
    return sha256;
  HASH_Begin(sha256_ctx);
  for (size_t i = 0; i < intermediates.size(); ++i) {
    CERTCertificate* ca_cert = intermediates[i];
    HASH_Update(sha256_ctx, ca_cert->derCert.data, ca_cert->derCert.len);
  }
  unsigned int result_len;
  HASH_End(sha256_ctx, sha256.data, &result_len,
           HASH_ResultLenContext(sha256_ctx));
  HASH_Destroy(sha256_ctx);

  return sha256;
}

// static
X509Certificate::OSCertHandle X509Certificate::ReadOSCertHandleFromPickle(
    base::PickleIterator* pickle_iter) {
  return x509_util::ReadOSCertHandleFromPickle(pickle_iter);
}

// static
bool X509Certificate::WriteOSCertHandleToPickle(OSCertHandle cert_handle,
                                                base::Pickle* pickle) {
  return pickle->WriteData(
      reinterpret_cast<const char*>(cert_handle->derCert.data),
      cert_handle->derCert.len);
}

// static
void X509Certificate::GetPublicKeyInfo(OSCertHandle cert_handle,
                                       size_t* size_bits,
                                       PublicKeyType* type) {
  x509_util::GetPublicKeyInfo(cert_handle, size_bits, type);
}

// static
bool X509Certificate::IsSelfSigned(OSCertHandle cert_handle) {
  crypto::ScopedSECKEYPublicKey public_key(CERT_ExtractPublicKey(cert_handle));
  if (!public_key.get())
    return false;
  if (SECSuccess != CERT_VerifySignedDataWithPublicKey(
                        &cert_handle->signatureWrap, public_key.get(), NULL)) {
    return false;
  }
  return CERT_CompareName(&cert_handle->subject, &cert_handle->issuer) ==
         SECEqual;
}

}  // namespace net

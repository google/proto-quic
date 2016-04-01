// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_util_ios.h"

#include <cert.h>
#include <CommonCrypto/CommonDigest.h>
#include <nss.h>
#include <prtypes.h>

#include "base/mac/scoped_cftyperef.h"
#include "base/memory/ref_counted.h"
#include "crypto/nss_util.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util_nss.h"

using base::ScopedCFTypeRef;

namespace net {
namespace x509_util_ios {

namespace {

// Creates an NSS certificate handle from |data|, which is |length| bytes in
// size.
CERTCertificate* CreateNSSCertHandleFromBytes(const char* data,
                                              int length) {
  if (length < 0)
    return NULL;

  crypto::EnsureNSSInit();

  if (!NSS_IsInitialized())
    return NULL;

  SECItem der_cert;
  der_cert.data = reinterpret_cast<unsigned char*>(const_cast<char*>(data));
  der_cert.len  = length;
  der_cert.type = siDERCertBuffer;

  // Parse into a certificate structure.
  return CERT_NewTempCertificate(CERT_GetDefaultCertDB(), &der_cert, NULL,
                                 PR_FALSE, PR_TRUE);
}

}  // namespace

CERTCertificate* CreateNSSCertHandleFromOSHandle(
    SecCertificateRef cert_handle) {
  ScopedCFTypeRef<CFDataRef> cert_data(SecCertificateCopyData(cert_handle));
  return CreateNSSCertHandleFromBytes(
      reinterpret_cast<const char*>(CFDataGetBytePtr(cert_data)),
      CFDataGetLength(cert_data));
}

SecCertificateRef CreateOSCertHandleFromNSSHandle(
    CERTCertificate* nss_cert_handle) {
  return X509Certificate::CreateOSCertHandleFromBytes(
      reinterpret_cast<const char*>(nss_cert_handle->derCert.data),
      nss_cert_handle->derCert.len);
}

scoped_refptr<X509Certificate> CreateCertFromNSSHandles(
    CERTCertificate* cert_handle,
    const std::vector<CERTCertificate*>& intermediates) {
  ScopedCFTypeRef<SecCertificateRef> os_server_cert(
      CreateOSCertHandleFromNSSHandle(cert_handle));
  if (!os_server_cert)
    return nullptr;
  std::vector<SecCertificateRef> os_intermediates;
  for (size_t i = 0; i < intermediates.size(); ++i) {
    SecCertificateRef intermediate =
        CreateOSCertHandleFromNSSHandle(intermediates[i]);
    if (!intermediate)
      break;
    os_intermediates.push_back(intermediate);
  }

  scoped_refptr<X509Certificate> cert = nullptr;
  if (intermediates.size() == os_intermediates.size()) {
    cert = X509Certificate::CreateFromHandle(os_server_cert,
                                             os_intermediates);
  }

  for (size_t i = 0; i < os_intermediates.size(); ++i)
    CFRelease(os_intermediates[i]);
  return cert;
}

SHA1HashValue CalculateFingerprintNSS(CERTCertificate* cert) {
  DCHECK(cert->derCert.data);
  DCHECK_NE(0U, cert->derCert.len);
  SHA1HashValue sha1;
  memset(sha1.data, 0, sizeof(sha1.data));
  CC_SHA1(cert->derCert.data, cert->derCert.len, sha1.data);
  return sha1;
}

// NSSCertificate implementation.

NSSCertificate::NSSCertificate(SecCertificateRef cert_handle) {
  nss_cert_handle_ = CreateNSSCertHandleFromOSHandle(cert_handle);
  DLOG_IF(ERROR, cert_handle && !nss_cert_handle_)
      << "Could not convert SecCertificateRef to CERTCertificate*";
}

NSSCertificate::~NSSCertificate() {
  CERT_DestroyCertificate(nss_cert_handle_);
}

CERTCertificate* NSSCertificate::cert_handle() const {
  return nss_cert_handle_;
}

// NSSCertChain implementation

NSSCertChain::NSSCertChain(X509Certificate* certificate) {
  DCHECK(certificate);
  certs_.push_back(CreateNSSCertHandleFromOSHandle(
      certificate->os_cert_handle()));
  const X509Certificate::OSCertHandles& cert_intermediates =
      certificate->GetIntermediateCertificates();
  for (size_t i = 0; i < cert_intermediates.size(); ++i)
    certs_.push_back(CreateNSSCertHandleFromOSHandle(cert_intermediates[i]));
}

NSSCertChain::~NSSCertChain() {
  for (size_t i = 0; i < certs_.size(); ++i)
    CERT_DestroyCertificate(certs_[i]);
}

CERTCertificate* NSSCertChain::cert_handle() const {
  return certs_.empty() ? NULL : certs_.front();
}

const std::vector<CERTCertificate*>& NSSCertChain::cert_chain() const {
  return certs_;
}

}  // namespace x509_util_ios
}  // namespace net

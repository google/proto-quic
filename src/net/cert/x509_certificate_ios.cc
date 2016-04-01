// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_certificate.h"

#include <CommonCrypto/CommonDigest.h>
#include <Security/Security.h>

#include <cert.h>
#include <cryptohi.h>
#include <keyhi.h>
#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <prtime.h>
#include <prtypes.h>
#include <secder.h>
#include <secerr.h>
#include <sslerr.h>

#include <vector>

#include "base/logging.h"
#include "base/mac/scoped_cftyperef.h"
#include "base/memory/scoped_ptr.h"
#include "base/numerics/safe_conversions.h"
#include "base/pickle.h"
#include "base/time/time.h"
#include "crypto/nss_util.h"
#include "crypto/scoped_nss_types.h"
#include "net/base/net_errors.h"
#include "net/cert/asn1_util.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/ev_root_ca_metadata.h"
#include "net/cert/x509_util_ios.h"
#include "net/cert/x509_util_nss.h"

using base::ScopedCFTypeRef;

namespace net {
namespace {
// Returns true if a given |cert_handle| is actually a valid X.509 certificate
// handle.
//
// SecCertificateCreateFromData() does not always force the immediate parsing of
// the certificate, and as such, may return a SecCertificateRef for an
// invalid/unparsable certificate. Force parsing to occur to ensure that the
// SecCertificateRef is correct. On later versions where
// SecCertificateCreateFromData() immediately parses, rather than lazily, this
// call is cheap, as the subject is cached.
bool IsValidOSCertHandle(SecCertificateRef cert_handle) {
  ScopedCFTypeRef<CFStringRef> sanity_check(
      SecCertificateCopySubjectSummary(cert_handle));
  return sanity_check != NULL;
}
}  // namespace

void X509Certificate::Initialize() {
  x509_util_ios::NSSCertificate nss_cert(cert_handle_);
  CERTCertificate* cert_handle = nss_cert.cert_handle();
  if (cert_handle) {
    x509_util::ParsePrincipal(&cert_handle->subject, &subject_);
    x509_util::ParsePrincipal(&cert_handle->issuer, &issuer_);
    x509_util::ParseDate(&cert_handle->validity.notBefore, &valid_start_);
    x509_util::ParseDate(&cert_handle->validity.notAfter, &valid_expiry_);
    serial_number_ = x509_util::ParseSerialNumber(cert_handle);
  }
  fingerprint_ = CalculateFingerprint(cert_handle_);
  ca_fingerprint_ = CalculateCAFingerprint(intermediate_ca_certs_);
}

bool X509Certificate::IsIssuedByEncoded(
    const std::vector<std::string>& valid_issuers) {
  x509_util_ios::NSSCertChain nss_chain(this);
  // Convert to scoped CERTName* list.
  std::vector<CERTName*> issuers;
  crypto::ScopedPLArenaPool arena(PORT_NewArena(DER_DEFAULT_CHUNKSIZE));
  if (!x509_util::GetIssuersFromEncodedList(valid_issuers,
                                            arena.get(),
                                            &issuers)) {
    return false;
  }
  return x509_util::IsCertificateIssuedBy(
      nss_chain.cert_chain(), issuers);
}

void X509Certificate::GetSubjectAltName(
    std::vector<std::string>* dns_names,
    std::vector<std::string>* ip_addrs) const {
  x509_util_ios::NSSCertificate nss_cert(cert_handle_);
  CERTCertificate* cert_handle = nss_cert.cert_handle();
  if (!cert_handle) {
    if (dns_names)
      dns_names->clear();
    if (ip_addrs)
      ip_addrs->clear();
    return;
  }
  x509_util::GetSubjectAltName(cert_handle, dns_names, ip_addrs);
}

// static
bool X509Certificate::GetDEREncoded(OSCertHandle cert_handle,
                                    std::string* encoded) {
  if (!cert_handle)
    return false;
  ScopedCFTypeRef<CFDataRef> der_data(SecCertificateCopyData(cert_handle));
  if (!der_data)
    return false;
  encoded->assign(reinterpret_cast<const char*>(CFDataGetBytePtr(der_data)),
                  CFDataGetLength(der_data));
  return true;
}

// static
bool X509Certificate::IsSameOSCert(X509Certificate::OSCertHandle a,
                                   X509Certificate::OSCertHandle b) {
  DCHECK(a && b);
  if (a == b)
    return true;
  if (CFEqual(a, b))
    return true;
  ScopedCFTypeRef<CFDataRef> a_data(SecCertificateCopyData(a));
  ScopedCFTypeRef<CFDataRef> b_data(SecCertificateCopyData(b));
  return a_data && b_data &&
         CFDataGetLength(a_data) == CFDataGetLength(b_data) &&
         memcmp(CFDataGetBytePtr(a_data), CFDataGetBytePtr(b_data),
                CFDataGetLength(a_data)) == 0;
}

// static
X509Certificate::OSCertHandle X509Certificate::CreateOSCertHandleFromBytes(
    const char* data,
    size_t length) {
  ScopedCFTypeRef<CFDataRef> cert_data(CFDataCreateWithBytesNoCopy(
      kCFAllocatorDefault, reinterpret_cast<const UInt8*>(data),
      base::checked_cast<CFIndex>(length), kCFAllocatorNull));
  if (!cert_data)
    return nullptr;
  OSCertHandle cert_handle = SecCertificateCreateWithData(NULL, cert_data);
  if (!cert_handle)
    return nullptr;
  if (!IsValidOSCertHandle(cert_handle)) {
    CFRelease(cert_handle);
    return nullptr;
  }
  return cert_handle;
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
    OSCertHandle handle) {
  if (!handle)
    return NULL;
  return reinterpret_cast<OSCertHandle>(const_cast<void*>(CFRetain(handle)));
}

// static
void X509Certificate::FreeOSCertHandle(OSCertHandle cert_handle) {
  if (cert_handle)
    CFRelease(cert_handle);
}

// static
SHA1HashValue X509Certificate::CalculateFingerprint(
    OSCertHandle cert) {
  SHA1HashValue sha1;
  memset(sha1.data, 0, sizeof(sha1.data));

  ScopedCFTypeRef<CFDataRef> cert_data(SecCertificateCopyData(cert));
  if (!cert_data)
    return sha1;
  DCHECK(CFDataGetBytePtr(cert_data));
  DCHECK_NE(0, CFDataGetLength(cert_data));
  CC_SHA1(CFDataGetBytePtr(cert_data), CFDataGetLength(cert_data), sha1.data);

  return sha1;
}

// static
SHA256HashValue X509Certificate::CalculateFingerprint256(OSCertHandle cert) {
  SHA256HashValue sha256;
  memset(sha256.data, 0, sizeof(sha256.data));

  ScopedCFTypeRef<CFDataRef> cert_data(SecCertificateCopyData(cert));
  if (!cert_data)
    return sha256;
  DCHECK(CFDataGetBytePtr(cert_data));
  DCHECK_NE(0, CFDataGetLength(cert_data));
  CC_SHA256(
      CFDataGetBytePtr(cert_data), CFDataGetLength(cert_data), sha256.data);

  return sha256;
}

// static
SHA1HashValue X509Certificate::CalculateCAFingerprint(
    const OSCertHandles& intermediates) {
  SHA1HashValue sha1;
  memset(sha1.data, 0, sizeof(sha1.data));

  // The CC_SHA(3cc) man page says all CC_SHA1_xxx routines return 1, so
  // we don't check their return values.
  CC_SHA1_CTX sha1_ctx;
  CC_SHA1_Init(&sha1_ctx);
  for (size_t i = 0; i < intermediates.size(); ++i) {
    ScopedCFTypeRef<CFDataRef>
        cert_data(SecCertificateCopyData(intermediates[i]));
    if (!cert_data)
      return sha1;
    CC_SHA1_Update(&sha1_ctx,
                   CFDataGetBytePtr(cert_data),
                   CFDataGetLength(cert_data));
  }
  CC_SHA1_Final(sha1.data, &sha1_ctx);
  return sha1;
}

// static
X509Certificate::OSCertHandle X509Certificate::ReadOSCertHandleFromPickle(
    base::PickleIterator* pickle_iter) {
  return x509_util::ReadOSCertHandleFromPickle(pickle_iter);
}

// static
bool X509Certificate::WriteOSCertHandleToPickle(OSCertHandle cert_handle,
                                                base::Pickle* pickle) {
  ScopedCFTypeRef<CFDataRef> cert_data(SecCertificateCopyData(cert_handle));
  if (!cert_data)
    return false;

  return pickle->WriteData(
      reinterpret_cast<const char*>(CFDataGetBytePtr(cert_data)),
      CFDataGetLength(cert_data));
}

// static
void X509Certificate::GetPublicKeyInfo(OSCertHandle cert_handle,
                                       size_t* size_bits,
                                       PublicKeyType* type) {
  x509_util_ios::NSSCertificate nss_cert(cert_handle);
  x509_util::GetPublicKeyInfo(nss_cert.cert_handle(), size_bits, type);
}

// static
bool X509Certificate::IsSelfSigned(OSCertHandle cert_handle) {
  x509_util_ios::NSSCertificate nss_cert(cert_handle);
  crypto::ScopedSECKEYPublicKey public_key(
      CERT_ExtractPublicKey(nss_cert.cert_handle()));
  if (!public_key.get())
    return false;
  return SECSuccess == CERT_VerifySignedDataWithPublicKey(
      &nss_cert.cert_handle()->signatureWrap, public_key.get(), NULL);
}

}  // namespace net

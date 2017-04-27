// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_certificate.h"

#include <CommonCrypto/CommonDigest.h>
#include <CoreServices/CoreServices.h>
#include <Security/Security.h>

#include <vector>

#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/mac/mac_logging.h"
#include "base/mac/scoped_cftyperef.h"
#include "base/memory/singleton.h"
#include "base/pickle.h"
#include "base/strings/string_piece.h"
#include "base/strings/sys_string_conversions.h"
#include "base/synchronization/lock.h"
#include "crypto/cssm_init.h"
#include "crypto/mac_security_services_lock.h"
#include "net/cert/x509_util_mac.h"

using base::ScopedCFTypeRef;
using base::Time;

namespace net {

// CSSM functions are deprecated as of OSX 10.7, but have no replacement.
// https://bugs.chromium.org/p/chromium/issues/detail?id=590914#c1
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

namespace {

bool GetCertDistinguishedName(
    const x509_util::CSSMCachedCertificate& cached_cert,
    const CSSM_OID* oid,
    CertPrincipal* result) {
  x509_util::CSSMFieldValue distinguished_name;
  OSStatus status = cached_cert.GetField(oid, &distinguished_name);
  if (status || !distinguished_name.field())
    return false;
  result->ParseDistinguishedName(distinguished_name.field()->Data,
                                 distinguished_name.field()->Length);
  return true;
}

bool IsCertIssuerInEncodedList(X509Certificate::OSCertHandle cert_handle,
                               const std::vector<std::string>& issuers) {
  x509_util::CSSMCachedCertificate cached_cert;
  if (cached_cert.Init(cert_handle) != CSSM_OK)
    return false;

  x509_util::CSSMFieldValue distinguished_name;
  OSStatus status = cached_cert.GetField(&CSSMOID_X509V1IssuerNameStd,
                                         &distinguished_name);
  if (status || !distinguished_name.field())
    return false;

  base::StringPiece name_piece(
      reinterpret_cast<const char*>(distinguished_name.field()->Data),
      static_cast<size_t>(distinguished_name.field()->Length));

  for (std::vector<std::string>::const_iterator it = issuers.begin();
       it != issuers.end(); ++it) {
    base::StringPiece issuer_piece(*it);
    if (name_piece == issuer_piece)
      return true;
  }

  return false;
}

bool GetCertDateForOID(const x509_util::CSSMCachedCertificate& cached_cert,
                       const CSSM_OID* oid,
                       Time* result) {
  *result = Time();

  x509_util::CSSMFieldValue field;
  OSStatus status = cached_cert.GetField(oid, &field);
  if (status)
    return false;

  const CSSM_X509_TIME* x509_time = field.GetAs<CSSM_X509_TIME>();
  if (x509_time->timeType != BER_TAG_UTC_TIME &&
      x509_time->timeType != BER_TAG_GENERALIZED_TIME) {
    LOG(ERROR) << "Unsupported date/time format "
               << x509_time->timeType;
    return false;
  }

  base::StringPiece time_string(
      reinterpret_cast<const char*>(x509_time->time.Data),
      x509_time->time.Length);
  CertDateFormat format = x509_time->timeType == BER_TAG_UTC_TIME ?
      CERT_DATE_FORMAT_UTC_TIME : CERT_DATE_FORMAT_GENERALIZED_TIME;
  if (!ParseCertificateDate(time_string, format, result)) {
    LOG(ERROR) << "Invalid certificate date/time " << time_string;
    return false;
  }
  return true;
}

std::string GetCertSerialNumber(
    const x509_util::CSSMCachedCertificate& cached_cert) {
  x509_util::CSSMFieldValue serial_number;
  OSStatus status = cached_cert.GetField(&CSSMOID_X509V1SerialNumber,
                                         &serial_number);
  if (status || !serial_number.field())
    return std::string();

  return std::string(
      reinterpret_cast<const char*>(serial_number.field()->Data),
      serial_number.field()->Length);
}

// Parses |data| of length |length|, attempting to decode it as the specified
// |format|. If |data| is in the specified format, any certificates contained
// within are stored into |output|.
void AddCertificatesFromBytes(const char* data, size_t length,
                              SecExternalFormat format,
                              X509Certificate::OSCertHandles* output) {
  SecExternalFormat input_format = format;
  ScopedCFTypeRef<CFDataRef> local_data(CFDataCreateWithBytesNoCopy(
      kCFAllocatorDefault, reinterpret_cast<const UInt8*>(data),
      base::checked_cast<CFIndex>(length), kCFAllocatorNull));

  CFArrayRef items = NULL;
  OSStatus status;
  {
    base::AutoLock lock(crypto::GetMacSecurityServicesLock());
    status = SecKeychainItemImport(local_data, NULL, &input_format,
                                   NULL, 0, NULL, NULL, &items);
  }

  if (status) {
    OSSTATUS_DLOG(WARNING, status)
        << "Unable to import items from data of length " << length;
    return;
  }

  ScopedCFTypeRef<CFArrayRef> scoped_items(items);
  CFTypeID cert_type_id = SecCertificateGetTypeID();

  for (CFIndex i = 0; i < CFArrayGetCount(items); ++i) {
    SecKeychainItemRef item = reinterpret_cast<SecKeychainItemRef>(
        const_cast<void*>(CFArrayGetValueAtIndex(items, i)));

    // While inputFormat implies only certificates will be imported, if/when
    // other formats (eg: PKCS#12) are supported, this may also include
    // private keys or other items types, so filter appropriately.
    if (CFGetTypeID(item) == cert_type_id) {
      SecCertificateRef cert = reinterpret_cast<SecCertificateRef>(item);
      // OS X ignores |input_format| if it detects that |local_data| is PEM
      // encoded, attempting to decode data based on internal rules for PEM
      // block headers. If a PKCS#7 blob is encoded with a PEM block of
      // CERTIFICATE, OS X 10.5 will return a single, invalid certificate
      // based on the decoded data. If this happens, the certificate should
      // not be included in |output|. Because |output| is empty,
      // CreateCertificateListfromBytes will use PEMTokenizer to decode the
      // data. When called again with the decoded data, OS X will honor
      // |input_format|, causing decode to succeed. On OS X 10.6, the data
      // is properly decoded as a PKCS#7, whether PEM or not, which avoids
      // the need to fallback to internal decoding.
      if (x509_util::IsValidSecCertificate(cert)) {
        CFRetain(cert);
        output->push_back(cert);
      }
    }
  }
}

}  // namespace

bool X509Certificate::Initialize() {
  x509_util::CSSMCachedCertificate cached_cert;
  if (cached_cert.Init(cert_handle_) != CSSM_OK)
    return false;
  serial_number_ = GetCertSerialNumber(cached_cert);

  return (!serial_number_.empty() &&
          GetCertDistinguishedName(cached_cert, &CSSMOID_X509V1SubjectNameStd,
                                   &subject_) &&
          GetCertDistinguishedName(cached_cert, &CSSMOID_X509V1IssuerNameStd,
                                   &issuer_) &&
          GetCertDateForOID(cached_cert, &CSSMOID_X509V1ValidityNotBefore,
                            &valid_start_) &&
          GetCertDateForOID(cached_cert, &CSSMOID_X509V1ValidityNotAfter,
                            &valid_expiry_));
}

bool X509Certificate::IsIssuedByEncoded(
    const std::vector<std::string>& valid_issuers) {
  if (IsCertIssuerInEncodedList(cert_handle_, valid_issuers))
    return true;

  for (OSCertHandles::iterator it = intermediate_ca_certs_.begin();
       it != intermediate_ca_certs_.end(); ++it) {
    if (IsCertIssuerInEncodedList(*it, valid_issuers))
      return true;
  }
  return false;
}

bool X509Certificate::GetSubjectAltName(
    std::vector<std::string>* dns_names,
    std::vector<std::string>* ip_addrs) const {
  if (dns_names)
    dns_names->clear();
  if (ip_addrs)
    ip_addrs->clear();

  x509_util::CSSMCachedCertificate cached_cert;
  OSStatus status = cached_cert.Init(cert_handle_);
  if (status)
    return false;

  x509_util::CSSMFieldValue subject_alt_name;
  status = cached_cert.GetField(&CSSMOID_SubjectAltName, &subject_alt_name);
  if (status || !subject_alt_name.field())
    return false;

  const CSSM_X509_EXTENSION* cssm_ext =
      subject_alt_name.GetAs<CSSM_X509_EXTENSION>();
  if (!cssm_ext || !cssm_ext->value.parsedValue)
    return false;
  const CE_GeneralNames* alt_name =
      reinterpret_cast<const CE_GeneralNames*>(cssm_ext->value.parsedValue);

  bool has_san = false;
  for (size_t name = 0; name < alt_name->numNames; ++name) {
    const CE_GeneralName& name_struct = alt_name->generalName[name];
    const CSSM_DATA& name_data = name_struct.name;
    // DNSName and IPAddress are encoded as IA5String and OCTET STRINGs
    // respectively, both of which can be byte copied from
    // CSSM_DATA::data into the appropriate output vector.
    if (name_struct.nameType == GNT_DNSName) {
      has_san = true;
      if (dns_names) {
        dns_names->push_back(std::string(
            reinterpret_cast<const char*>(name_data.Data), name_data.Length));
      }
    } else if (name_struct.nameType == GNT_IPAddress) {
      has_san = true;
      if (ip_addrs) {
        ip_addrs->push_back(std::string(
            reinterpret_cast<const char*>(name_data.Data), name_data.Length));
      }
    }
    // Fast path: Found at least one subjectAltName and the caller doesn't
    // need the actual values.
    if (has_san && !ip_addrs && !dns_names)
      return true;
  }

  return has_san;
}

// static
bool X509Certificate::GetDEREncoded(X509Certificate::OSCertHandle cert_handle,
                                    std::string* encoded) {
  CSSM_DATA der_data;
  if (!cert_handle || SecCertificateGetData(cert_handle, &der_data) != noErr)
    return false;
  encoded->assign(reinterpret_cast<char*>(der_data.Data),
                  der_data.Length);
  return true;
}

// static
bool X509Certificate::IsSameOSCert(X509Certificate::OSCertHandle a,
                                   X509Certificate::OSCertHandle b) {
  DCHECK(a && b);
  return CFEqual(a, b);
}

// static
X509Certificate::OSCertHandle X509Certificate::CreateOSCertHandleFromBytes(
    const char* data,
    size_t length) {
  return x509_util::CreateSecCertificateFromBytes(
             reinterpret_cast<const uint8_t*>(data), length)
      .release();
}

// static
X509Certificate::OSCertHandles X509Certificate::CreateOSCertHandlesFromBytes(
    const char* data,
    size_t length,
    Format format) {
  OSCertHandles results;

  switch (format) {
    case FORMAT_SINGLE_CERTIFICATE: {
      OSCertHandle handle = CreateOSCertHandleFromBytes(data, length);
      if (handle)
        results.push_back(handle);
      break;
    }
    case FORMAT_PKCS7:
      AddCertificatesFromBytes(data, length, kSecFormatPKCS7, &results);
      break;
    default:
      NOTREACHED() << "Certificate format " << format << " unimplemented";
      break;
  }

  return results;
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
SHA256HashValue X509Certificate::CalculateFingerprint256(OSCertHandle cert) {
  return x509_util::CalculateFingerprint256(cert);
}

// static
SHA256HashValue X509Certificate::CalculateCAFingerprint256(
    const OSCertHandles& intermediates) {
  SHA256HashValue sha256;
  memset(sha256.data, 0, sizeof(sha256.data));

  // The CC_SHA(3cc) man page says all CC_SHA256_xxx routines return 1, so
  // we don't check their return values.
  CC_SHA256_CTX sha256_ctx;
  CC_SHA256_Init(&sha256_ctx);
  CSSM_DATA cert_data;
  for (size_t i = 0; i < intermediates.size(); ++i) {
    OSStatus status = SecCertificateGetData(intermediates[i], &cert_data);
    if (status)
      return sha256;
    CC_SHA256_Update(&sha256_ctx, cert_data.Data, cert_data.Length);
  }
  CC_SHA256_Final(sha256.data, &sha256_ctx);

  return sha256;
}

// static
X509Certificate::OSCertHandle X509Certificate::ReadOSCertHandleFromPickle(
    base::PickleIterator* pickle_iter) {
  const char* data;
  int length;
  if (!pickle_iter->ReadData(&data, &length))
    return NULL;

  return CreateOSCertHandleFromBytes(data, length);
}

// static
bool X509Certificate::WriteOSCertHandleToPickle(OSCertHandle cert_handle,
                                                base::Pickle* pickle) {
  CSSM_DATA cert_data;
  OSStatus status = SecCertificateGetData(cert_handle, &cert_data);
  if (status)
    return false;

  return pickle->WriteData(reinterpret_cast<char*>(cert_data.Data),
                           cert_data.Length);
}

// static
void X509Certificate::GetPublicKeyInfo(OSCertHandle cert_handle,
                                       size_t* size_bits,
                                       PublicKeyType* type) {
  // Since we might fail, set the output parameters to default values first.
  *type = kPublicKeyTypeUnknown;
  *size_bits = 0;

  SecKeyRef key;
  OSStatus status = SecCertificateCopyPublicKey(cert_handle, &key);
  if (status) {
    // SecCertificateCopyPublicKey may fail if the certificate has an invalid
    // key. See https://crbug.com/472291.
    LOG(WARNING) << "SecCertificateCopyPublicKey failed: " << status;
    return;
  }
  ScopedCFTypeRef<SecKeyRef> scoped_key(key);

  const CSSM_KEY* cssm_key;
  status = SecKeyGetCSSMKey(key, &cssm_key);
  if (status) {
    NOTREACHED() << "SecKeyGetCSSMKey failed: " << status;
    return;
  }

  *size_bits = cssm_key->KeyHeader.LogicalKeySizeInBits;

  switch (cssm_key->KeyHeader.AlgorithmId) {
    case CSSM_ALGID_RSA:
      *type = kPublicKeyTypeRSA;
      break;
    case CSSM_ALGID_DSA:
      *type = kPublicKeyTypeDSA;
      break;
    case CSSM_ALGID_ECDSA:
      *type = kPublicKeyTypeECDSA;
      break;
    case CSSM_ALGID_DH:
      *type = kPublicKeyTypeDH;
      break;
    default:
      *type = kPublicKeyTypeUnknown;
      *size_bits = 0;
      break;
  }
}

// static
bool X509Certificate::IsSelfSigned(OSCertHandle cert_handle) {
  return x509_util::IsSelfSigned(cert_handle);
}

#pragma clang diagnostic pop  // "-Wdeprecated-declarations"

}  // namespace net

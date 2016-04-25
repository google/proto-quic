// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_X509_UTIL_NSS_H_
#define NET_CERT_X509_UTIL_NSS_H_

#include <stddef.h>

#include <string>
#include <vector>

#include "base/time/time.h"
#include "net/base/net_export.h"
#include "net/cert/x509_certificate.h"

namespace base {
class PickleIterator;
}

typedef struct CERTCertificateStr CERTCertificate;
typedef struct CERTNameStr CERTName;
typedef struct PK11SlotInfoStr PK11SlotInfo;
typedef struct PLArenaPool PLArenaPool;
typedef struct SECItemStr SECItem;

namespace net {

namespace x509_util {

#if defined(USE_NSS_CERTS)
// Parses the Principal attribute from |name| and outputs the result in
// |principal|.
void ParsePrincipal(CERTName* name,
                    CertPrincipal* principal);

// Parses the date from |der_date| and outputs the result in |result|.
void ParseDate(const SECItem* der_date, base::Time* result);

// Parses the serial number from |certificate|.
std::string ParseSerialNumber(const CERTCertificate* certificate);

// Gets the dNSName and iPAddress name types from the subjectAltName
// extension of |cert_handle|, storing them in |dns_names| and
// |ip_addrs|, respectively.
// If no subjectAltName is present, or no names of that type are
// present, the relevant vectors are cleared.
void GetSubjectAltName(CERTCertificate* cert_handle,
                       std::vector<std::string>* dns_names,
                       std::vector<std::string>* ip_addrs);

// Stores the values of all rfc822Name subjectAltNames from |cert_handle|
// into |names|. If no names are present, clears |names|.
// WARNING: This method does not validate that the rfc822Name is
// properly encoded; it MAY contain embedded NULs or other illegal
// characters; care should be taken to validate the well-formedness
// before using.
NET_EXPORT void GetRFC822SubjectAltNames(CERTCertificate* cert_handle,
                                         std::vector<std::string>* names);

// Stores the values of all Microsoft UPN subjectAltNames from |cert_handle|
// into |names|. If no names are present, clears |names|.
//
// A "Microsoft UPN subjectAltName" is an OtherName value whose type-id
// is equal to 1.3.6.1.4.1.311.20.2.3 (known as either id-ms-san-sc-logon-upn,
// as described in RFC 4556, or as szOID_NT_PRINCIPAL_NAME, as
// documented in Microsoft KB287547).
// The value field is a UTF8String literal.
// For more information:
//   https://www.ietf.org/mail-archive/web/pkix/current/msg03145.html
//   https://www.ietf.org/proceedings/65/slides/pkix-4/sld1.htm
//   https://tools.ietf.org/html/rfc4556
//
// WARNING: This method does not validate that the name is
// properly encoded; it MAY contain embedded NULs or other illegal
// characters; care should be taken to validate the well-formedness
// before using.
NET_EXPORT void GetUPNSubjectAltNames(CERTCertificate* cert_handle,
                                      std::vector<std::string>* names);

// Creates all possible OS certificate handles from |data| encoded in a specific
// |format|. Returns an empty collection on failure.
X509Certificate::OSCertHandles CreateOSCertHandlesFromBytes(
    const char* data,
    size_t length,
    X509Certificate::Format format);

// Reads a single certificate from |pickle_iter| and returns a platform-specific
// certificate handle. Returns an invalid handle, NULL, on failure.
X509Certificate::OSCertHandle ReadOSCertHandleFromPickle(
    base::PickleIterator* pickle_iter);

// Sets |*size_bits| to be the length of the public key in bits, and sets
// |*type| to one of the |PublicKeyType| values. In case of
// |kPublicKeyTypeUnknown|, |*size_bits| will be set to 0.
void GetPublicKeyInfo(CERTCertificate* handle,
                      size_t* size_bits,
                      X509Certificate::PublicKeyType* type);

// Create a list of CERTName objects from a list of DER-encoded X.509
// DistinguishedName items. All objects are created in a given arena.
// |encoded_issuers| is the list of encoded DNs.
// |arena| is the arena used for all allocations.
// |out| will receive the result list on success.
// Return true on success. On failure, the caller must free the
// intermediate CERTName objects pushed to |out|.
bool GetIssuersFromEncodedList(
    const std::vector<std::string>& issuers,
    PLArenaPool* arena,
    std::vector<CERTName*>* out);

// Returns true iff a certificate is issued by any of the issuers listed
// by name in |valid_issuers|.
// |cert_chain| is the certificate's chain.
// |valid_issuers| is a list of strings, where each string contains
// a DER-encoded X.509 Distinguished Name.
bool IsCertificateIssuedBy(const std::vector<CERTCertificate*>& cert_chain,
                           const std::vector<CERTName*>& valid_issuers);

// Generates a unique nickname for |slot|, returning |nickname| if it is
// already unique.
//
// Note: The nickname returned will NOT include the token name, thus the
// token name must be prepended if calling an NSS function that expects
// <token>:<nickname>.
// TODO(gspencer): Internationalize this: it's wrong to hard-code English.
std::string GetUniqueNicknameForSlot(const std::string& nickname,
                                     const SECItem* subject,
                                     PK11SlotInfo* slot);
#endif  // defined(USE_NSS_CERTS)

} // namespace x509_util

} // namespace net

#endif  // NET_CERT_X509_UTIL_NSS_H_

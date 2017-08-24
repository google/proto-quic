// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_X509_UTIL_NSS_H_
#define NET_CERT_X509_UTIL_NSS_H_

#include <stddef.h>

#include <string>
#include <vector>

#include "net/base/net_export.h"
#include "net/cert/cert_type.h"
#include "net/cert/scoped_nss_types.h"
#include "net/cert/x509_certificate.h"

typedef struct CERTCertificateStr CERTCertificate;
typedef struct CERTNameStr CERTName;
typedef struct PK11SlotInfoStr PK11SlotInfo;
typedef struct SECItemStr SECItem;

namespace net {

namespace x509_util {

// Returns true if two certificate handles refer to identical certificates.
NET_EXPORT bool IsSameCertificate(CERTCertificate* a, CERTCertificate* b);
NET_EXPORT bool IsSameCertificate(CERTCertificate* a, const X509Certificate* b);
NET_EXPORT bool IsSameCertificate(const X509Certificate* a, CERTCertificate* b);

// Returns a CERTCertificate handle from the DER-encoded representation. The
// returned value may reference an already existing CERTCertificate object.
// Returns NULL on failure.
NET_EXPORT ScopedCERTCertificate
CreateCERTCertificateFromBytes(const uint8_t* data, size_t length);

// Returns a CERTCertificate handle from |cert|. The returned value may
// reference an already existing CERTCertificate object.  Returns NULL on
// failure.
NET_EXPORT ScopedCERTCertificate
CreateCERTCertificateFromX509Certificate(const X509Certificate* cert);

// Returns a vector of CERTCertificates corresponding to |cert| and its
// intermediates (if any). Returns an empty vector on failure.
NET_EXPORT ScopedCERTCertificateList
CreateCERTCertificateListFromX509Certificate(const X509Certificate* cert);

// Parses all of the certificates possible from |data|. |format| is a
// bit-wise OR of X509Certificate::Format, indicating the possible formats the
// certificates may have been serialized as. If an error occurs, an empty
// collection will be returned.
NET_EXPORT ScopedCERTCertificateList
CreateCERTCertificateListFromBytes(const char* data, size_t length, int format);

// Increments the refcount of |cert| and returns a handle for that reference.
NET_EXPORT ScopedCERTCertificate DupCERTCertificate(CERTCertificate* cert);

// Creates an X509Certificate from |cert|, with intermediates from |chain|.
// Returns NULL on failure.
NET_EXPORT scoped_refptr<X509Certificate>
CreateX509CertificateFromCERTCertificate(
    CERTCertificate* cert,
    const std::vector<CERTCertificate*>& chain);

// Creates an X509Certificate from |cert|, with no intermediates.
// Returns NULL on failure.
NET_EXPORT scoped_refptr<X509Certificate>
CreateX509CertificateFromCERTCertificate(CERTCertificate* cert);

// Obtains the DER encoded certificate data for |cert|. On success, returns
// true and writes the DER encoded certificate to |*der_encoded|.
NET_EXPORT bool GetDEREncoded(CERTCertificate* cert, std::string* der_encoded);

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

// Generates a unique nickname for |nss_cert| based on the |type| and |slot|.
NET_EXPORT std::string GetDefaultUniqueNickname(CERTCertificate* nss_cert,
                                                CertType type,
                                                PK11SlotInfo* slot);

// Returns a name that can be used to represent the principal.  It tries in
// this order: CN, O and OU and returns the first non-empty one found.
// This mirrors net::CertPrincipal::GetDisplayName.
NET_EXPORT std::string GetCERTNameDisplayName(CERTName* name);

} // namespace x509_util

} // namespace net

#endif  // NET_CERT_X509_UTIL_NSS_H_

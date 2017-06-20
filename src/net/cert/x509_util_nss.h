// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_X509_UTIL_NSS_H_
#define NET_CERT_X509_UTIL_NSS_H_

#include <stddef.h>

#include <string>
#include <vector>

#include "net/base/net_export.h"

typedef struct CERTCertificateStr CERTCertificate;
typedef struct PK11SlotInfoStr PK11SlotInfo;
typedef struct SECItemStr SECItem;

namespace net {

namespace x509_util {

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

} // namespace x509_util

} // namespace net

#endif  // NET_CERT_X509_UTIL_NSS_H_

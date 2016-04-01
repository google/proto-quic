// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_ASN1_UTIL_H_
#define NET_CERT_ASN1_UTIL_H_

#include <vector>

#include "base/strings/string_piece.h"
#include "net/base/net_export.h"

namespace net {

namespace asn1 {

// ExtractSPKIFromDERCert parses the DER encoded certificate in |cert| and
// extracts the bytes of the SubjectPublicKeyInfo. On successful return,
// |spki_out| is set to contain the SPKI, pointing into |cert|.
NET_EXPORT_PRIVATE bool ExtractSPKIFromDERCert(base::StringPiece cert,
                                               base::StringPiece* spki_out);

// ExtractSubjectPublicKeyFromSPKI parses the DER encoded SubjectPublicKeyInfo
// in |spki| and extracts the bytes of the SubjectPublicKey. On successful
// return, |spk_out| is set to contain the public key, pointing into |spki|.
NET_EXPORT_PRIVATE bool ExtractSubjectPublicKeyFromSPKI(
    base::StringPiece spki,
    base::StringPiece* spk_out);

// ExtractCRLURLsFromDERCert parses the DER encoded certificate in |cert| and
// extracts the URL of each CRL. On successful return, the elements of
// |urls_out| point into |cert|.
//
// CRLs that only cover a subset of the reasons are omitted as the spec
// requires that at least one CRL be included that covers all reasons.
//
// CRLs that use an alternative issuer are also omitted.
//
// The nested set of GeneralNames is flattened into a single list because
// having several CRLs with one location is equivalent to having one CRL with
// several locations as far as a CRL filter is concerned.
NET_EXPORT_PRIVATE bool ExtractCRLURLsFromDERCert(
    base::StringPiece cert,
    std::vector<base::StringPiece>* urls_out);

} // namespace asn1

} // namespace net

#endif // NET_CERT_ASN1_UTIL_H_

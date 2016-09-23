/*
 * NSS utility functions
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "net/third_party/nss/ssl/cmpcert.h"

#include <secder.h>
#include <secitem.h>

#include "base/strings/string_piece.h"

namespace net {

bool MatchClientCertificateIssuers(
    CERTCertificate* cert,
    const std::vector<std::string>& cert_authorities,
    std::vector<ScopedCERTCertificate>* intermediates) {
  // Bound how many iterations to try.
  static const int kMaxDepth = 20;

  intermediates->clear();

  // If no authorities are supplied, everything matches.
  if (cert_authorities.empty())
    return true;

  CERTCertificate* curcert = cert;
  while (intermediates->size() < kMaxDepth) {
    base::StringPiece issuer(
        reinterpret_cast<const char*>(curcert->derIssuer.data),
        curcert->derIssuer.len);

    // Check if |curcert| is signed by a valid CA.
    for (const std::string& ca : cert_authorities) {
      if (issuer == ca)
        return true;
    }

    // Stop at self-issued certificates.
    if (SECITEM_CompareItem(&curcert->derIssuer, &curcert->derSubject) ==
        SECEqual) {
      return false;
    }

    // Look the parent up in the database and keep searching.
    curcert = CERT_FindCertByName(curcert->dbhandle, &curcert->derIssuer);
    if (!curcert)
      return false;
    intermediates->emplace_back(curcert);
  }

  return false;
}

}  // namespace net

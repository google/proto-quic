// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_TRUST_STORE_H_
#define NET_CERT_INTERNAL_TRUST_STORE_H_

#include <vector>

#include "base/memory/ref_counted.h"
#include "net/base/net_export.h"
#include "net/cert/internal/parsed_certificate.h"

namespace net {

namespace der {
class Input;
}

// A TrustAnchor represents a trust anchor used during RFC 5280 path validation.
//
// At its core, each trust anchor has two parts:
//  * Name
//  * Public Key
//
// Optionally a trust anchor may contain:
//  * An associated certificate (used when pretty-printing)
//  * Mandatory trust anchor constraints
//
// Relationship between ParsedCertificate and TrustAnchor:
//
// For convenience trust anchors are often described using a
// (self-signed) certificate. TrustAnchor facilitates this by allowing
// construction of a TrustAnchor given a ParsedCertificate.
//
// When constructing a TrustAnchor from a certificate there are different
// interpretations for the meaning of properties other than the Subject and
// SPKI in the certificate.
//
// * CreateFromCertificateNoConstraints() -- Extracts the Subject and SPKI from
// the source certificate. ALL other information in the certificate is
// considered irrelevant during path validation.
//
// * CreateFromCertificateWithConstraints() -- Extracts the Subject and SPKI
// from the source certificate, and additionally interprets some properties of
// the source certificate as mandatory anchor constraints.
//
// Trust anchor constraints are described in more detail by RFC 5937. This
// implementation follows that description, and fixes
// "enforceTrustAnchorConstraints" to true.
class NET_EXPORT TrustAnchor : public base::RefCountedThreadSafe<TrustAnchor> {
 public:
  // Creates a TrustAnchor given a certificate. The ONLY parts of the
  // certificate that are relevant to the resulting trust anchor are:
  //
  //  * Subject
  //  * SPKI
  //
  // Everything else, including the source certiticate's expiration, basic
  // constraints, policy constraints, etc is not used.
  //
  // This is the common interpretation for a trust anchor when given as a
  // certificate.
  static scoped_refptr<TrustAnchor> CreateFromCertificateNoConstraints(
      scoped_refptr<ParsedCertificate> cert);

  // Creates a TrustAnchor given a certificate. The resulting trust anchor is
  // initialized using the source certificate's subject and SPKI as usual,
  // however other parts of the certificate are applied as anchor constraints.
  //
  // The implementation matches the properties identified by RFC 5937,
  // resulting in the following hodgepodge of enforcement on the source
  // certificate:
  //
  //  * Signature:             No
  //  * Validity (expiration): No
  //  * Key usage:             No
  //  * Extended key usage:    No
  //  * Basic constraints:     Yes, but only the pathlen (CA=false is accepted)
  //  * Name constraints:      Yes
  //  * Certificate policies:  Not currently, TODO(crbug.com/634453)
  //  * inhibitAnyPolicy:      Not currently, TODO(crbug.com/634453)
  //  * PolicyConstraints:     Not currently, TODO(crbug.com/634452)
  //
  // The presence of any other unrecognized extension marked as critical fails
  // validation.
  static scoped_refptr<TrustAnchor> CreateFromCertificateWithConstraints(
      scoped_refptr<ParsedCertificate> cert);

  der::Input spki() const;
  der::Input normalized_subject() const;

  // Returns the optional certificate representing this trust anchor.
  // In the current implementation it will never return nullptr...
  // however clients should be prepared to handle this case.
  const scoped_refptr<ParsedCertificate>& cert() const;

  // Returns true if the trust anchor has attached (mandatory) trust anchor
  // constraints. This returns true when the anchor was constructed using
  // CreateFromCertificateWithConstraints.
  bool enforces_constraints() const { return enforces_constraints_; }

 private:
  friend class base::RefCountedThreadSafe<TrustAnchor>;
  TrustAnchor(scoped_refptr<ParsedCertificate>, bool enforces_constraints);
  ~TrustAnchor();

  scoped_refptr<ParsedCertificate> cert_;
  bool enforces_constraints_ = false;
};

using TrustAnchors = std::vector<scoped_refptr<TrustAnchor>>;

// Interface for finding trust anchors.
class NET_EXPORT TrustStore {
 public:
  TrustStore();
  virtual ~TrustStore();

  // Appends the trust anchors that match |cert|'s issuer name to |*matches|.
  // |cert| and |matches| must not be null.
  virtual void FindTrustAnchorsForCert(
      const scoped_refptr<ParsedCertificate>& cert,
      TrustAnchors* matches) const = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(TrustStore);
};

}  // namespace net

#endif  // NET_CERT_INTERNAL_TRUST_STORE_H_

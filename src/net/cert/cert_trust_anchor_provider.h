// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_CERT_TRUST_ANCHOR_PROVIDER_H_
#define NET_CERT_CERT_TRUST_ANCHOR_PROVIDER_H_

#include <vector>

#include "base/memory/ref_counted.h"
#include "net/base/net_export.h"

namespace net {

class X509Certificate;
typedef std::vector<scoped_refptr<X509Certificate> > CertificateList;

// Interface to retrieve the current list of additional trust anchors.
// This is used by CertVerifier to get a list of anchors to trust in addition to
// the anchors known to the CertVerifier.
class NET_EXPORT CertTrustAnchorProvider {
 public:
  virtual ~CertTrustAnchorProvider() {}

  // Returns a list of certificates to be used as trust anchors during
  // certificate validation, in addition to (eg: the union of) any pre-existing
  // or pre-configured trust anchors.
  virtual const CertificateList& GetAdditionalTrustAnchors() = 0;
};

}  // namespace net

#endif  // NET_CERT_CERT_TRUST_ANCHOR_PROVIDER_H_

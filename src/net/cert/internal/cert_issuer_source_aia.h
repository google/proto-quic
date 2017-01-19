// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_CERT_ISSUER_SOURCE_AIA_H_
#define NET_CERT_INTERNAL_CERT_ISSUER_SOURCE_AIA_H_

#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/cert/internal/cert_issuer_source.h"

namespace net {

class CertNetFetcher;

class NET_EXPORT CertIssuerSourceAia : public CertIssuerSource {
 public:
  // Creates CertIssuerSource that will use |cert_fetcher| to retrieve issuers
  // using AuthorityInfoAccess URIs. CertIssuerSourceAia must be created and
  // used only on a single thread, which is the thread |cert_fetcher| will be
  // operated from.
  explicit CertIssuerSourceAia(scoped_refptr<CertNetFetcher> cert_fetcher);
  ~CertIssuerSourceAia() override;

  // CertIssuerSource implementation:
  void SyncGetIssuersOf(const ParsedCertificate* cert,
                        ParsedCertificateList* issuers) override;
  void AsyncGetIssuersOf(const ParsedCertificate* cert,
                         std::unique_ptr<Request>* out_req) override;

 private:
  scoped_refptr<CertNetFetcher> cert_fetcher_;

  DISALLOW_COPY_AND_ASSIGN(CertIssuerSourceAia);
};

}  // namespace net

#endif  // NET_CERT_INTERNAL_CERT_ISSUER_SOURCE_AIA_H_

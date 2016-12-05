// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/trust_store_collection.h"

namespace net {

TrustStoreCollection::TrustStoreCollection() = default;
TrustStoreCollection::~TrustStoreCollection() = default;

void TrustStoreCollection::AddTrustStore(TrustStore* store) {
  DCHECK(store);
  stores_.push_back(store);
}

void TrustStoreCollection::FindTrustAnchorsForCert(
    const scoped_refptr<ParsedCertificate>& cert,
    TrustAnchors* matches) const {
  for (auto* store : stores_) {
    store->FindTrustAnchorsForCert(cert, matches);
  }
}

}  // namespace net

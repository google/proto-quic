// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/trust_store_collection.h"

namespace net {

TrustStoreCollection::TrustStoreCollection() = default;
TrustStoreCollection::~TrustStoreCollection() = default;

void TrustStoreCollection::SetPrimaryTrustStore(TrustStore* store) {
  DCHECK(!primary_store_);
  DCHECK(store);
  primary_store_ = store;
}

void TrustStoreCollection::AddTrustStoreSynchronousOnly(TrustStore* store) {
  DCHECK(store);
  sync_only_stores_.push_back(store);
}

void TrustStoreCollection::FindTrustAnchorsForCert(
    const scoped_refptr<ParsedCertificate>& cert,
    const TrustAnchorsCallback& callback,
    TrustAnchors* synchronous_matches,
    std::unique_ptr<Request>* out_req) const {
  if (primary_store_)
    primary_store_->FindTrustAnchorsForCert(cert, callback, synchronous_matches,
                                            out_req);

  for (auto* store : sync_only_stores_) {
    store->FindTrustAnchorsForCert(cert, TrustAnchorsCallback(),
                                   synchronous_matches, nullptr);
  }
}

}  // namespace net

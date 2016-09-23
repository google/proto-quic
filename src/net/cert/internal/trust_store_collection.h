// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_TRUST_STORE_COLLECTION_H_
#define NET_CERT_INTERNAL_TRUST_STORE_COLLECTION_H_

#include "base/memory/ref_counted.h"
#include "net/base/net_export.h"
#include "net/cert/internal/trust_store.h"

namespace base {
class TaskRunner;
}

namespace net {

// TrustStoreCollection is an implementation of TrustStore which combines the
// results from multiple TrustStores.
//
// The synchronous matches will be in order from the primary store, and then
// from the secondary stores in the order they were added to the
// TrustStoreCollection.
//
// Currently only one "primary" store can be added that supports async queries,
// any number of additional, synchronous-only stores can be used. (The
// assumption is that the async one would be useful for OS integration, while
// the sync only stores can be used for supplying additional anchors. If
// multiple async stores are desired, it might be worth changing the
// FindTrustAnchorsForCert interface so that it can return async results in
// multiple batches.)
class NET_EXPORT TrustStoreCollection : public TrustStore {
 public:
  TrustStoreCollection();
  ~TrustStoreCollection() override;

  // Includes results from |store| in the combined output. Both sync and async
  // queries to |store| will be allowed. |store| must outlive the
  // TrustStoreCollection.
  void SetPrimaryTrustStore(TrustStore* store);

  // Includes results from |store| in the combined output. |store| will only be
  // queried synchronously. |store| must outlive the TrustStoreCollection.
  void AddTrustStoreSynchronousOnly(TrustStore* store);

  // TrustStore implementation:
  void FindTrustAnchorsForCert(
      const scoped_refptr<ParsedCertificate>& cert,
      const TrustAnchorsCallback& callback,
      TrustAnchors* synchronous_matches,
      std::unique_ptr<Request>* out_req) const override;

 private:
  TrustStore* primary_store_ = nullptr;
  std::vector<TrustStore*> sync_only_stores_;

  DISALLOW_COPY_AND_ASSIGN(TrustStoreCollection);
};

}  // namespace net

#endif  // NET_CERT_INTERNAL_TRUST_STORE_COLLECTION_H_

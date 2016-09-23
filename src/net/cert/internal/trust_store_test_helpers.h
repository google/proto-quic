// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_TRUST_STORE_TEST_HELPERS_H_
#define NET_CERT_INTERNAL_TRUST_STORE_TEST_HELPERS_H_

#include "base/callback.h"
#include "base/run_loop.h"
#include "net/cert/internal/trust_store.h"
#include "net/cert/internal/trust_store_in_memory.h"

namespace net {

// Deletes the Request owned by |*req_owner|, then calls done_callback. Intended
// to be passed as the TrustAnchorsCallback to FindTrustAnchorsForCert to test
// deleting the Request during the request callback.
void TrustStoreRequestDeleter(std::unique_ptr<TrustStore::Request>* req_owner,
                              const base::Closure& done_callback,
                              TrustAnchors anchors);

// Helper to record async results from a FindTrustAnchorsForCert call.
class TrustAnchorResultRecorder {
 public:
  TrustAnchorResultRecorder();
  ~TrustAnchorResultRecorder();

  TrustStore::TrustAnchorsCallback Callback();

  void Run() { run_loop_.Run(); }

  const TrustAnchors& matches() const { return anchors_; }

 private:
  void OnGotAnchors(TrustAnchors anchors);

  base::RunLoop run_loop_;
  TrustAnchors anchors_;
};

// In-memory TrustStore that can return results synchronously, asynchronously,
// or both.
class TrustStoreInMemoryAsync : public TrustStore {
 public:
  TrustStoreInMemoryAsync();
  ~TrustStoreInMemoryAsync() override;

  // Adds |anchor| to the set of results that will be returned synchronously.
  void AddSyncTrustAnchor(scoped_refptr<TrustAnchor> anchor);

  // Adds |anchor| to the set of results that will be returned asynchronously.
  void AddAsyncTrustAnchor(scoped_refptr<TrustAnchor> anchor);

  // TrustStore implementation:
  void FindTrustAnchorsForCert(
      const scoped_refptr<ParsedCertificate>& cert,
      const TrustAnchorsCallback& callback,
      TrustAnchors* synchronous_matches,
      std::unique_ptr<Request>* out_req) const override;

 private:
  TrustStoreInMemory sync_store_;
  TrustStoreInMemory async_store_;
};

}  // namespace net

#endif  // NET_CERT_INTERNAL_TRUST_STORE_TEST_HELPERS_H_

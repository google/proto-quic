// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/trust_store_test_helpers.h"

#include "base/bind.h"
#include "base/callback_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/memory/weak_ptr.h"
#include "base/threading/thread_task_runner_handle.h"

namespace net {

namespace {

class TrustStoreInMemoryAsyncRequest : public TrustStore::Request {
 public:
  explicit TrustStoreInMemoryAsyncRequest(
      const TrustStore::TrustAnchorsCallback& callback)
      : callback_(callback), weak_ptr_factory_(this) {}

  void PostTrustCallback(TrustAnchors anchors) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(&TrustStoreInMemoryAsyncRequest::DoTrustCallback,
                   weak_ptr_factory_.GetWeakPtr(), std::move(anchors)));
  }

 private:
  void DoTrustCallback(TrustAnchors anchors) {
    base::ResetAndReturn(&callback_).Run(std::move(anchors));
    // |this| may be deleted here.
  }

  TrustStore::TrustAnchorsCallback callback_;
  base::WeakPtrFactory<TrustStoreInMemoryAsyncRequest> weak_ptr_factory_;
};

}  // namespace

void TrustStoreRequestDeleter(std::unique_ptr<TrustStore::Request>* req_owner,
                              const base::Closure& done_callback,
                              TrustAnchors anchors) {
  req_owner->reset();
  done_callback.Run();
}

TrustAnchorResultRecorder::TrustAnchorResultRecorder() = default;
TrustAnchorResultRecorder::~TrustAnchorResultRecorder() = default;

TrustStore::TrustAnchorsCallback TrustAnchorResultRecorder::Callback() {
  return base::Bind(&TrustAnchorResultRecorder::OnGotAnchors,
                    base::Unretained(this));
}

void TrustAnchorResultRecorder::OnGotAnchors(TrustAnchors anchors) {
  anchors_ = std::move(anchors);
  run_loop_.Quit();
}

TrustStoreInMemoryAsync::TrustStoreInMemoryAsync() = default;
TrustStoreInMemoryAsync::~TrustStoreInMemoryAsync() = default;

void TrustStoreInMemoryAsync::AddSyncTrustAnchor(
    scoped_refptr<TrustAnchor> anchor) {
  sync_store_.AddTrustAnchor(std::move(anchor));
}

void TrustStoreInMemoryAsync::AddAsyncTrustAnchor(
    scoped_refptr<TrustAnchor> anchor) {
  async_store_.AddTrustAnchor(std::move(anchor));
}

void TrustStoreInMemoryAsync::FindTrustAnchorsForCert(
    const scoped_refptr<ParsedCertificate>& cert,
    const TrustAnchorsCallback& callback,
    TrustAnchors* synchronous_matches,
    std::unique_ptr<Request>* out_req) const {
  sync_store_.FindTrustAnchorsForCert(cert, TrustAnchorsCallback(),
                                      synchronous_matches, nullptr);
  if (!callback.is_null()) {
    TrustAnchors async_matches;
    async_store_.FindTrustAnchorsForCert(cert, TrustAnchorsCallback(),
                                         &async_matches, nullptr);

    std::unique_ptr<TrustStoreInMemoryAsyncRequest> req(
        base::MakeUnique<TrustStoreInMemoryAsyncRequest>(callback));
    req->PostTrustCallback(std::move(async_matches));

    *out_req = std::move(req);
  }
}

}  // namespace net

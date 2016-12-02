// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_TRUST_STORE_IN_MEMORY_H_
#define NET_CERT_INTERNAL_TRUST_STORE_IN_MEMORY_H_

#include <unordered_map>

#include "base/memory/ref_counted.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/cert/internal/trust_store.h"

namespace net {

// A very simple implementation of a TrustStore, which contains a set of
// trust anchors.
class NET_EXPORT TrustStoreInMemory : public TrustStore {
 public:
  TrustStoreInMemory();
  ~TrustStoreInMemory() override;

  // Empties the trust store, resetting it to original state.
  void Clear();

  void AddTrustAnchor(scoped_refptr<TrustAnchor> anchor);

  // TrustStore implementation:
  void FindTrustAnchorsForCert(const scoped_refptr<ParsedCertificate>& cert,
                               TrustAnchors* matches) const override;

 private:
  // Multimap from normalized subject -> TrustAnchor.
  std::unordered_multimap<base::StringPiece,
                          scoped_refptr<TrustAnchor>,
                          base::StringPieceHash>
      anchors_;

  DISALLOW_COPY_AND_ASSIGN(TrustStoreInMemory);
};

}  // namespace net

#endif  // NET_CERT_INTERNAL_TRUST_STORE_IN_MEMORY_H_

// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_TEST_TOOLS_FAILING_PROOF_SOURCE_H_
#define NET_QUIC_TEST_TOOLS_FAILING_PROOF_SOURCE_H_

#include "net/quic/core/crypto/proof_source.h"

namespace net {
namespace test {

class FailingProofSource : public ProofSource {
 public:
  void GetProof(const QuicSocketAddress& server_address,
                const std::string& hostname,
                const std::string& server_config,
                QuicVersion quic_version,
                base::StringPiece chlo_hash,
                const QuicTagVector& connection_options,
                std::unique_ptr<Callback> callback) override;
};

}  // namespace test
}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_FAILING_PROOF_SOURCE_H_

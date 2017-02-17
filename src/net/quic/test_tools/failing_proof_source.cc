// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/failing_proof_source.h"

namespace net {
namespace test {

void FailingProofSource::GetProof(const QuicSocketAddress& server_address,
                                  const std::string& hostname,
                                  const std::string& server_config,
                                  QuicVersion quic_version,
                                  base::StringPiece chlo_hash,
                                  const QuicTagVector& connection_options,
                                  std::unique_ptr<Callback> callback) {
  callback->Run(false, nullptr, QuicCryptoProof(), nullptr);
}

}  // namespace test
}  // namespace net

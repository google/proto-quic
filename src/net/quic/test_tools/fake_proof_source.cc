// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/fake_proof_source.h"
#include "net/quic/test_tools/crypto_test_utils.h"

using std::string;

namespace net {
namespace test {

FakeProofSource::FakeProofSource()
    : delegate_(CryptoTestUtils::ProofSourceForTesting()) {}

FakeProofSource::~FakeProofSource() {}

FakeProofSource::Params::Params(const IPAddress& server_ip,
                                std::string hostname,
                                std::string server_config,
                                QuicVersion quic_version,
                                std::string chlo_hash,
                                const QuicTagVector& connection_options,
                                std::unique_ptr<ProofSource::Callback> callback)
    : server_ip(server_ip),
      hostname(hostname),
      server_config(server_config),
      quic_version(quic_version),
      chlo_hash(chlo_hash),
      connection_options(connection_options),
      callback(std::move(callback)) {}

FakeProofSource::Params::~Params() {}

FakeProofSource::Params::Params(FakeProofSource::Params&& other) = default;

FakeProofSource::Params& FakeProofSource::Params::operator=(
    FakeProofSource::Params&& other) = default;

void FakeProofSource::Activate() {
  active_ = true;
}

bool FakeProofSource::GetProof(const IPAddress& server_ip,
                               const string& hostname,
                               const string& server_config,
                               QuicVersion quic_version,
                               StringPiece chlo_hash,
                               const QuicTagVector& connection_options,
                               scoped_refptr<ProofSource::Chain>* out_chain,
                               string* out_signature,
                               string* out_leaf_cert_sct) {
  LOG(WARNING) << "Synchronous GetProof called";
  return delegate_->GetProof(server_ip, hostname, server_config, quic_version,
                             chlo_hash, connection_options, out_chain,
                             out_signature, out_leaf_cert_sct);
}

void FakeProofSource::GetProof(
    const IPAddress& server_ip,
    const string& hostname,
    const string& server_config,
    QuicVersion quic_version,
    StringPiece chlo_hash,
    const QuicTagVector& connection_options,
    std::unique_ptr<ProofSource::Callback> callback) {
  if (!active_) {
    scoped_refptr<Chain> chain;
    string signature;
    string leaf_cert_sct;
    const bool ok =
        GetProof(server_ip, hostname, server_config, quic_version, chlo_hash,
                 connection_options, &chain, &signature, &leaf_cert_sct);
    callback->Run(ok, chain, signature, leaf_cert_sct,
                  /* details = */ nullptr);
    return;
  }

  LOG(WARNING) << "Asynchronous GetProof called";
  params_.push_back(Params{server_ip, hostname, server_config, quic_version,
                           chlo_hash.as_string(), connection_options,
                           std::move(callback)});
}

int FakeProofSource::NumPendingCallbacks() const {
  return params_.size();
}

void FakeProofSource::InvokePendingCallback(int n) {
  CHECK(NumPendingCallbacks() > n);

  const Params& params = params_[n];

  scoped_refptr<ProofSource::Chain> chain;
  string signature;
  string leaf_cert_sct;
  const bool ok = delegate_->GetProof(
      params.server_ip, params.hostname, params.server_config,
      params.quic_version, params.chlo_hash, params.connection_options, &chain,
      &signature, &leaf_cert_sct);

  params.callback->Run(ok, chain, signature, leaf_cert_sct,
                       /* details = */ nullptr);
  auto it = params_.begin() + n;
  params_.erase(it);
}

}  // namespace test
}  // namespace net

// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/multiplexed_http_stream.h"

#include "base/logging.h"

namespace net {

MultiplexedHttpStream::MultiplexedHttpStream(MultiplexedSessionHandle session)
    : session_(session) {}

MultiplexedHttpStream::~MultiplexedHttpStream() {}

bool MultiplexedHttpStream::GetRemoteEndpoint(IPEndPoint* endpoint) {
  return session_.GetRemoteEndpoint(endpoint);
}

void MultiplexedHttpStream::GetSSLInfo(SSLInfo* ssl_info) {
  session_.GetSSLInfo(ssl_info);
}

void MultiplexedHttpStream::SaveSSLInfo() {
  session_.SaveSSLInfo();
}

void MultiplexedHttpStream::GetSSLCertRequestInfo(
    SSLCertRequestInfo* cert_request_info) {
  // A multiplexed stream cannot request client certificates. Client
  // authentication may only occur during the initial SSL handshake.
  NOTREACHED();
}

Error MultiplexedHttpStream::GetTokenBindingSignature(
    crypto::ECPrivateKey* key,
    TokenBindingType tb_type,
    std::vector<uint8_t>* out) {
  return session_.GetTokenBindingSignature(key, tb_type, out);
}

void MultiplexedHttpStream::Drain(HttpNetworkSession* session) {
  NOTREACHED();
  Close(false);
  delete this;
}

HttpStream* MultiplexedHttpStream::RenewStreamForAuth() {
  return nullptr;
}

void MultiplexedHttpStream::SetConnectionReused() {}

bool MultiplexedHttpStream::CanReuseConnection() const {
  // Multiplexed streams aren't considered reusable.
  return false;
}

}  // namespace net

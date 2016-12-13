// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_MULTIPLEXED_HTTP_STREAM_H_
#define NET_SPDY_MULTIPLEXED_HTTP_STREAM_H_

#include "net/http/http_stream.h"
#include "net/spdy/multiplexed_session.h"

namespace net {

// Base class for SPDY and QUIC HttpStream subclasses.
class NET_EXPORT_PRIVATE MultiplexedHttpStream : public HttpStream {
 public:
  explicit MultiplexedHttpStream(MultiplexedSessionHandle session);
  ~MultiplexedHttpStream() override;

  bool GetRemoteEndpoint(IPEndPoint* endpoint) override;
  void GetSSLInfo(SSLInfo* ssl_info) override;
  void GetSSLCertRequestInfo(SSLCertRequestInfo* cert_request_info) override;
  Error GetTokenBindingSignature(crypto::ECPrivateKey* key,
                                 TokenBindingType tb_type,
                                 std::vector<uint8_t>* out) override;
  void Drain(HttpNetworkSession* session) override;
  HttpStream* RenewStreamForAuth() override;
  void SetConnectionReused() override;
  bool CanReuseConnection() const override;

  // Caches SSL info from the underlying session.
  void SaveSSLInfo();

 private:
  MultiplexedSessionHandle session_;
};

}  // namespace net

#endif  // NET_SPDY_MULTIPLEXED_HTTP_STREAM_H_

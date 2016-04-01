// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// HttpBasicStream is a simple implementation of HttpStream.  It assumes it is
// not sharing a sharing with any other HttpStreams, therefore it just reads and
// writes directly to the Http Stream.

#ifndef NET_HTTP_HTTP_BASIC_STREAM_H_
#define NET_HTTP_HTTP_BASIC_STREAM_H_

#include <stdint.h>

#include <string>

#include "base/macros.h"
#include "net/http/http_basic_state.h"
#include "net/http/http_stream.h"

namespace net {

class BoundNetLog;
class ClientSocketHandle;
class HttpResponseInfo;
struct HttpRequestInfo;
class HttpRequestHeaders;
class HttpStreamParser;
class IOBuffer;

class HttpBasicStream : public HttpStream {
 public:
  // Constructs a new HttpBasicStream. InitializeStream must be called to
  // initialize it correctly.
  HttpBasicStream(ClientSocketHandle* connection, bool using_proxy);
  ~HttpBasicStream() override;

  // HttpStream methods:
  int InitializeStream(const HttpRequestInfo* request_info,
                       RequestPriority priority,
                       const BoundNetLog& net_log,
                       const CompletionCallback& callback) override;

  int SendRequest(const HttpRequestHeaders& headers,
                  HttpResponseInfo* response,
                  const CompletionCallback& callback) override;

  UploadProgress GetUploadProgress() const override;

  int ReadResponseHeaders(const CompletionCallback& callback) override;

  int ReadResponseBody(IOBuffer* buf,
                       int buf_len,
                       const CompletionCallback& callback) override;

  void Close(bool not_reusable) override;

  HttpStream* RenewStreamForAuth() override;

  bool IsResponseBodyComplete() const override;

  bool IsConnectionReused() const override;

  void SetConnectionReused() override;

  bool CanReuseConnection() const override;

  int64_t GetTotalReceivedBytes() const override;

  int64_t GetTotalSentBytes() const override;

  bool GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const override;

  void GetSSLInfo(SSLInfo* ssl_info) override;

  void GetSSLCertRequestInfo(SSLCertRequestInfo* cert_request_info) override;

  bool GetRemoteEndpoint(IPEndPoint* endpoint) override;

  Error GetSignedEKMForTokenBinding(crypto::ECPrivateKey* key,
                                    std::vector<uint8_t>* out) override;

  void Drain(HttpNetworkSession* session) override;

  void PopulateNetErrorDetails(NetErrorDetails* details) override;

  void SetPriority(RequestPriority priority) override;

 private:
  HttpStreamParser* parser() const { return state_.parser(); }

  HttpBasicState state_;

  DISALLOW_COPY_AND_ASSIGN(HttpBasicStream);
};

}  // namespace net

#endif  // NET_HTTP_HTTP_BASIC_STREAM_H_

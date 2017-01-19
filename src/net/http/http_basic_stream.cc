// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_basic_stream.h"

#include <utility>

#include "net/http/http_request_info.h"
#include "net/http/http_response_body_drainer.h"
#include "net/http/http_stream_parser.h"
#include "net/socket/client_socket_handle.h"

namespace net {

HttpBasicStream::HttpBasicStream(std::unique_ptr<ClientSocketHandle> connection,
                                 bool using_proxy,
                                 bool http_09_on_non_default_ports_enabled)
    : state_(std::move(connection),
             using_proxy,
             http_09_on_non_default_ports_enabled) {}

HttpBasicStream::~HttpBasicStream() {}

int HttpBasicStream::InitializeStream(const HttpRequestInfo* request_info,
                                      RequestPriority priority,
                                      const NetLogWithSource& net_log,
                                      const CompletionCallback& callback) {
  state_.Initialize(request_info, priority, net_log, callback);
  return OK;
}

int HttpBasicStream::SendRequest(const HttpRequestHeaders& headers,
                                 HttpResponseInfo* response,
                                 const CompletionCallback& callback) {
  DCHECK(parser());
  return parser()->SendRequest(
      state_.GenerateRequestLine(), headers, response, callback);
}

int HttpBasicStream::ReadResponseHeaders(const CompletionCallback& callback) {
  return parser()->ReadResponseHeaders(callback);
}

int HttpBasicStream::ReadResponseBody(IOBuffer* buf,
                                      int buf_len,
                                      const CompletionCallback& callback) {
  return parser()->ReadResponseBody(buf, buf_len, callback);
}

void HttpBasicStream::Close(bool not_reusable) {
  // parser() is null if |this| is created by an orphaned
  // HttpStreamFactoryImpl::Job in which case InitializeStream() will not have
  // been called.
  if (parser())
    parser()->Close(not_reusable);
}

HttpStream* HttpBasicStream::RenewStreamForAuth() {
  DCHECK(IsResponseBodyComplete());
  DCHECK(!parser()->IsMoreDataBuffered());
  // The HttpStreamParser object still has a pointer to the connection. Just to
  // be extra-sure it doesn't touch the connection again, delete it here rather
  // than leaving it until the destructor is called.
  state_.DeleteParser();
  return new HttpBasicStream(state_.ReleaseConnection(), state_.using_proxy(),
                             state_.http_09_on_non_default_ports_enabled());
}

bool HttpBasicStream::IsResponseBodyComplete() const {
  return parser()->IsResponseBodyComplete();
}

bool HttpBasicStream::IsConnectionReused() const {
  return parser()->IsConnectionReused();
}

void HttpBasicStream::SetConnectionReused() { parser()->SetConnectionReused(); }

bool HttpBasicStream::CanReuseConnection() const {
  return parser()->CanReuseConnection();
}

int64_t HttpBasicStream::GetTotalReceivedBytes() const {
  if (parser())
    return parser()->received_bytes();
  return 0;
}

int64_t HttpBasicStream::GetTotalSentBytes() const {
  if (parser())
    return parser()->sent_bytes();
  return 0;
}

bool HttpBasicStream::GetLoadTimingInfo(
    LoadTimingInfo* load_timing_info) const {
  return state_.connection()->GetLoadTimingInfo(IsConnectionReused(),
                                                load_timing_info);
}

void HttpBasicStream::GetSSLInfo(SSLInfo* ssl_info) {
  parser()->GetSSLInfo(ssl_info);
}

void HttpBasicStream::GetSSLCertRequestInfo(
    SSLCertRequestInfo* cert_request_info) {
  parser()->GetSSLCertRequestInfo(cert_request_info);
}

bool HttpBasicStream::GetRemoteEndpoint(IPEndPoint* endpoint) {
  if (!state_.connection() || !state_.connection()->socket())
    return false;

  return state_.connection()->socket()->GetPeerAddress(endpoint) == OK;
}

Error HttpBasicStream::GetTokenBindingSignature(crypto::ECPrivateKey* key,
                                                TokenBindingType tb_type,
                                                std::vector<uint8_t>* out) {
  return parser()->GetTokenBindingSignature(key, tb_type, out);
}

void HttpBasicStream::Drain(HttpNetworkSession* session) {
  HttpResponseBodyDrainer* drainer = new HttpResponseBodyDrainer(this);
  drainer->Start(session);
  // |drainer| will delete itself.
}

void HttpBasicStream::PopulateNetErrorDetails(NetErrorDetails* details) {
  // TODO(mmenke):  Consumers don't actually care about HTTP version, but seems
  // like the right version should be reported, if headers were received.
  details->connection_info = HttpResponseInfo::CONNECTION_INFO_HTTP1_1;
  return;
}

void HttpBasicStream::SetPriority(RequestPriority priority) {
  // TODO(akalin): Plumb this through to |connection_|.
}

}  // namespace net

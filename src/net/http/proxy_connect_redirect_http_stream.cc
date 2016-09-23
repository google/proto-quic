// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/proxy_connect_redirect_http_stream.h"

#include <cstddef>

#include "base/logging.h"
#include "net/base/net_errors.h"

namespace net {

ProxyConnectRedirectHttpStream::ProxyConnectRedirectHttpStream(
    LoadTimingInfo* load_timing_info)
    : has_load_timing_info_(load_timing_info != NULL) {
  if (has_load_timing_info_)
    load_timing_info_ = *load_timing_info;
}

ProxyConnectRedirectHttpStream::~ProxyConnectRedirectHttpStream() {}

int ProxyConnectRedirectHttpStream::InitializeStream(
    const HttpRequestInfo* request_info,
    RequestPriority priority,
    const NetLogWithSource& net_log,
    const CompletionCallback& callback) {
  NOTREACHED();
  return OK;
}

int ProxyConnectRedirectHttpStream::SendRequest(
    const HttpRequestHeaders& request_headers,
    HttpResponseInfo* response,
    const CompletionCallback& callback) {
  NOTREACHED();
  return OK;
}

int ProxyConnectRedirectHttpStream::ReadResponseHeaders(
    const CompletionCallback& callback) {
  NOTREACHED();
  return OK;
}

int ProxyConnectRedirectHttpStream::ReadResponseBody(
    IOBuffer* buf,
    int buf_len,
    const CompletionCallback& callback) {
  NOTREACHED();
  return OK;
}

void ProxyConnectRedirectHttpStream::Close(bool not_reusable) {}

bool ProxyConnectRedirectHttpStream::IsResponseBodyComplete() const {
  NOTREACHED();
  return true;
}

bool ProxyConnectRedirectHttpStream::IsConnectionReused() const {
  NOTREACHED();
  return false;
}

void ProxyConnectRedirectHttpStream::SetConnectionReused() {
  NOTREACHED();
}

bool ProxyConnectRedirectHttpStream::CanReuseConnection() const {
  return false;
}

int64_t ProxyConnectRedirectHttpStream::GetTotalReceivedBytes() const {
  return 0;
}

int64_t ProxyConnectRedirectHttpStream::GetTotalSentBytes() const {
  return 0;
}

bool ProxyConnectRedirectHttpStream::GetLoadTimingInfo(
    LoadTimingInfo* load_timing_info) const {
  if (!has_load_timing_info_)
    return false;

  *load_timing_info = load_timing_info_;
  return true;
}

void ProxyConnectRedirectHttpStream::GetSSLInfo(SSLInfo* ssl_info) {
  NOTREACHED();
}

void ProxyConnectRedirectHttpStream::GetSSLCertRequestInfo(
    SSLCertRequestInfo* cert_request_info) {
  NOTREACHED();
}

bool ProxyConnectRedirectHttpStream::GetRemoteEndpoint(IPEndPoint* endpoint) {
  NOTREACHED();
  return false;
}

Error ProxyConnectRedirectHttpStream::GetTokenBindingSignature(
    crypto::ECPrivateKey* key,
    TokenBindingType tb_type,
    std::vector<uint8_t>* out) {
  NOTREACHED();
  return ERR_NOT_IMPLEMENTED;
}

void ProxyConnectRedirectHttpStream::Drain(HttpNetworkSession* session) {
  NOTREACHED();
}

void ProxyConnectRedirectHttpStream::PopulateNetErrorDetails(
    NetErrorDetails* /*details*/) {
  return;
}

void ProxyConnectRedirectHttpStream::SetPriority(RequestPriority priority) {
  // Nothing to do.
}

HttpStream* ProxyConnectRedirectHttpStream::RenewStreamForAuth() {
  NOTREACHED();
  return NULL;
}

}  // namespace

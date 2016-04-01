// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/proxy_client_socket.h"

#include "base/metrics/histogram_macros.h"
#include "base/strings/stringprintf.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_errors.h"
#include "net/http/http_auth_controller.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "url/gurl.h"

namespace net {

namespace {

void CopyHeaderValues(scoped_refptr<HttpResponseHeaders> source,
                      scoped_refptr<HttpResponseHeaders> dest,
                      const std::string& header_name) {
  size_t iter = 0;
  std::string header_value;

  while (source->EnumerateHeader(&iter, header_name, &header_value))
    dest->AddHeader(header_name + ": " + header_value);
}

}  // namespace

// static
void ProxyClientSocket::BuildTunnelRequest(
    const HostPortPair& endpoint,
    const HttpRequestHeaders& auth_headers,
    const std::string& user_agent,
    std::string* request_line,
    HttpRequestHeaders* request_headers) {
  // RFC 7230 Section 5.4 says a client MUST send a Host header field in all
  // HTTP/1.1 request messages, and Host SHOULD be the first header field
  // following the request-line.  Add "Proxy-Connection: keep-alive" for compat
  // with HTTP/1.0 proxies such as Squid (required for NTLM authentication).
  std::string host_and_port = endpoint.ToString();
  *request_line =
      base::StringPrintf("CONNECT %s HTTP/1.1\r\n", host_and_port.c_str());
  request_headers->SetHeader(HttpRequestHeaders::kHost, host_and_port);
  request_headers->SetHeader(HttpRequestHeaders::kProxyConnection,
                             "keep-alive");
  if (!user_agent.empty())
    request_headers->SetHeader(HttpRequestHeaders::kUserAgent, user_agent);

  request_headers->MergeFrom(auth_headers);
}

// static
int ProxyClientSocket::HandleProxyAuthChallenge(HttpAuthController* auth,
                                                HttpResponseInfo* response,
                                                const BoundNetLog& net_log) {
  DCHECK(response->headers.get());
  int rv = auth->HandleAuthChallenge(response->headers, response->ssl_info,
                                     false, true, net_log);
  response->auth_challenge = auth->auth_info();
  if (rv == OK)
    return ERR_PROXY_AUTH_REQUESTED;
  return rv;
}

// static
void ProxyClientSocket::LogBlockedTunnelResponse(int http_status_code,
                                                 bool is_https_proxy) {
  if (is_https_proxy) {
    UMA_HISTOGRAM_CUSTOM_ENUMERATION(
        "Net.BlockedTunnelResponse.HttpsProxy",
        HttpUtil::MapStatusCodeForHistogram(http_status_code),
        HttpUtil::GetStatusCodesForHistogram());
  } else {
    UMA_HISTOGRAM_CUSTOM_ENUMERATION(
        "Net.BlockedTunnelResponse.HttpProxy",
        HttpUtil::MapStatusCodeForHistogram(http_status_code),
        HttpUtil::GetStatusCodesForHistogram());
  }
}

// static
bool ProxyClientSocket::SanitizeProxyAuth(HttpResponseInfo* response) {
  DCHECK(response && response->headers.get());

  scoped_refptr<HttpResponseHeaders> old_headers = response->headers;

  const char kHeaders[] = "HTTP/1.1 407 Proxy Authentication Required\n\n";
  scoped_refptr<HttpResponseHeaders> new_headers = new HttpResponseHeaders(
      HttpUtil::AssembleRawHeaders(kHeaders, arraysize(kHeaders)));

  // Copy status line and all hop-by-hop headers to preserve keep-alive
  // behavior.
  new_headers->ReplaceStatusLine(old_headers->GetStatusLine());
  CopyHeaderValues(old_headers, new_headers, "connection");
  CopyHeaderValues(old_headers, new_headers, "proxy-connection");
  CopyHeaderValues(old_headers, new_headers, "keep-alive");
  CopyHeaderValues(old_headers, new_headers, "trailer");
  CopyHeaderValues(old_headers, new_headers, "transfer-encoding");
  CopyHeaderValues(old_headers, new_headers, "upgrade");

  CopyHeaderValues(old_headers, new_headers, "content-length");

  CopyHeaderValues(old_headers, new_headers, "proxy-authenticate");

  response->headers = new_headers;
  return true;
}

// static
bool ProxyClientSocket::SanitizeProxyRedirect(HttpResponseInfo* response) {
  DCHECK(response && response->headers.get());

  std::string location;
  if (!response->headers->IsRedirect(&location))
    return false;

  // Return minimal headers; set "Content-Length: 0" to ignore response body.
  std::string fake_response_headers = base::StringPrintf(
      "HTTP/1.0 302 Found\n"
      "Location: %s\n"
      "Content-Length: 0\n"
      "Connection: close\n"
      "\n",
      location.c_str());
  std::string raw_headers =
      HttpUtil::AssembleRawHeaders(fake_response_headers.data(),
                                   fake_response_headers.length());
  response->headers = new HttpResponseHeaders(raw_headers);

  return true;
}

}  // namespace net

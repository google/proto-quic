// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/embedded_test_server/http_response.h"

#include "base/format_macros.h"
#include "base/logging.h"
#include "base/strings/stringprintf.h"
#include "net/http/http_status_code.h"

namespace net {
namespace test_server {

HttpResponse::~HttpResponse() {
}

RawHttpResponse::RawHttpResponse(const std::string& headers,
                                 const std::string& contents)
    : headers_(headers), contents_(contents) {}

RawHttpResponse::~RawHttpResponse() {}

void RawHttpResponse::SendResponse(const SendBytesCallback& send,
                                   const SendCompleteCallback& done) {
  std::string response;
  if (!headers_.empty())
    response = headers_ + "\r\n" + contents_;
  else
    response = contents_;
  send.Run(response, done);
}

void RawHttpResponse::AddHeader(const std::string& key_value_pair) {
  headers_.append(base::StringPrintf("%s\r\n", key_value_pair.c_str()));
}

BasicHttpResponse::BasicHttpResponse() : code_(HTTP_OK) {
}

BasicHttpResponse::~BasicHttpResponse() {
}

std::string BasicHttpResponse::ToResponseString() const {
  // Response line with headers.
  std::string response_builder;

  std::string http_reason_phrase(GetHttpReasonPhrase(code_));

  // TODO(mtomasz): For http/1.0 requests, send http/1.0.
  base::StringAppendF(&response_builder,
                      "HTTP/1.1 %d %s\r\n",
                      code_,
                      http_reason_phrase.c_str());
  base::StringAppendF(&response_builder, "Connection: close\r\n");

  base::StringAppendF(&response_builder, "Content-Length: %" PRIuS "\r\n",
                      content_.size());
  base::StringAppendF(&response_builder, "Content-Type: %s\r\n",
                      content_type_.c_str());
  for (size_t i = 0; i < custom_headers_.size(); ++i) {
    const std::string& header_name = custom_headers_[i].first;
    const std::string& header_value = custom_headers_[i].second;
    DCHECK(header_value.find_first_of("\n\r") == std::string::npos) <<
        "Malformed header value.";
    base::StringAppendF(&response_builder,
                        "%s: %s\r\n",
                        header_name.c_str(),
                        header_value.c_str());
  }
  base::StringAppendF(&response_builder, "\r\n");

  return response_builder + content_;
}

void BasicHttpResponse::SendResponse(const SendBytesCallback& send,
                                     const SendCompleteCallback& done) {
  send.Run(ToResponseString(), done);
}

}  // namespace test_server
}  // namespace net

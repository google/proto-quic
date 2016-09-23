// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/url_request/url_request_hanging_read_job.h"

#include <string>

#include "base/bind.h"
#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_util.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_filter.h"

namespace net {
namespace {

const char kMockHostname[] = "mock.hanging.read";

GURL GetMockUrl(const std::string& scheme, const std::string& hostname) {
  return GURL(scheme + "://" + hostname + "/");
}

class MockJobInterceptor : public URLRequestInterceptor {
 public:
  MockJobInterceptor() {}
  ~MockJobInterceptor() override {}

  // URLRequestInterceptor implementation
  URLRequestJob* MaybeInterceptRequest(
      URLRequest* request,
      NetworkDelegate* network_delegate) const override {
    return new URLRequestHangingReadJob(request, network_delegate);
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(MockJobInterceptor);
};

}  // namespace

URLRequestHangingReadJob::URLRequestHangingReadJob(
    URLRequest* request,
    NetworkDelegate* network_delegate)
    : URLRequestJob(request, network_delegate),
      content_length_(10),  // non-zero content-length
      weak_factory_(this) {}

void URLRequestHangingReadJob::Start() {
  // Start reading asynchronously so that all error reporting and data
  // callbacks happen as they would for network requests.
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&URLRequestHangingReadJob::StartAsync,
                            weak_factory_.GetWeakPtr()));
}

URLRequestHangingReadJob::~URLRequestHangingReadJob() {}

int URLRequestHangingReadJob::ReadRawData(IOBuffer* buf, int buf_size) {
  // Make read hang. It never completes.
  return ERR_IO_PENDING;
}

int URLRequestHangingReadJob::GetResponseCode() const {
  HttpResponseInfo info;
  GetResponseInfoConst(&info);
  return info.headers->response_code();
}

// Public virtual version.
void URLRequestHangingReadJob::GetResponseInfo(HttpResponseInfo* info) {
  // Forward to private const version.
  GetResponseInfoConst(info);
}

// Private const version.
void URLRequestHangingReadJob::GetResponseInfoConst(
    HttpResponseInfo* info) const {
  // Send back mock headers.
  std::string raw_headers;
  raw_headers.append(
      "HTTP/1.1 200 OK\n"
      "Content-type: text/plain\n");
  raw_headers.append(
      base::StringPrintf("Content-Length: %1d\n", content_length_));
  info->headers = new HttpResponseHeaders(HttpUtil::AssembleRawHeaders(
      raw_headers.c_str(), static_cast<int>(raw_headers.length())));
}

void URLRequestHangingReadJob::StartAsync() {
  set_expected_content_size(content_length_);
  NotifyHeadersComplete();
}

// static
void URLRequestHangingReadJob::AddUrlHandler() {
  // Add |hostname| to URLRequestFilter for HTTP and HTTPS.
  URLRequestFilter* filter = URLRequestFilter::GetInstance();
  filter->AddHostnameInterceptor("http", kMockHostname,
                                 base::MakeUnique<MockJobInterceptor>());
  filter->AddHostnameInterceptor("https", kMockHostname,
                                 base::MakeUnique<MockJobInterceptor>());
}

// static
GURL URLRequestHangingReadJob::GetMockHttpUrl() {
  return GetMockUrl("http", kMockHostname);
}

// static
GURL URLRequestHangingReadJob::GetMockHttpsUrl() {
  return GetMockUrl("https", kMockHostname);
}

}  // namespace net

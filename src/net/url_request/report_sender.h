// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_URL_REQUEST_REPORT_SENDER_H_
#define NET_URL_REQUEST_REPORT_SENDER_H_

#include <memory>
#include <set>
#include <string>

#include "base/callback.h"
#include "base/macros.h"
#include "net/http/transport_security_state.h"
#include "net/url_request/url_request.h"

class GURL;

namespace net {

class URLRequestContext;

// ReportSender asynchronously sends serialized reports to a URI.
// It takes serialized reports as a sequence of bytes so as to be agnostic to
// the format of the report being sent (JSON, protobuf, etc.) and the particular
// data that it contains. Multiple reports can be in-flight at once. This class
// owns inflight requests and cleans them up when necessary.
class NET_EXPORT ReportSender
    : public URLRequest::Delegate,
      public TransportSecurityState::ReportSenderInterface {
 public:
  using ErrorCallback = base::Callback<void(const GURL&, int)>;

  // Represents whether or not to send cookies along with reports.
  enum CookiesPreference { SEND_COOKIES, DO_NOT_SEND_COOKIES };

  // Constructs a ReportSender that sends reports with the
  // given |request_context| and includes or excludes cookies based on
  // |cookies_preference|. |request_context| must outlive the
  // ReportSender.
  ReportSender(URLRequestContext* request_context,
               CookiesPreference cookies_preference);

  // Constructs a ReportSender that sends reports with the
  // given |request_context| and includes or excludes cookies based on
  // |cookies_preference|. |request_context| must outlive the
  // ReportSender. When sending a report results in an error,
  // |error_callback| is called with the report URI and net error as
  // arguments.
  ReportSender(URLRequestContext* request_context,
               CookiesPreference cookies_preference,
               const ErrorCallback& error_callback);

  ~ReportSender() override;

  // TransportSecurityState::ReportSenderInterface implementation.
  void Send(const GURL& report_uri, const std::string& report) override;
  void SetErrorCallback(const ErrorCallback& error_callback) override;

  // net::URLRequest::Delegate implementation.
  void OnResponseStarted(URLRequest* request, int net_error) override;
  void OnReadCompleted(URLRequest* request, int bytes_read) override;

 private:
  net::URLRequestContext* const request_context_;

  CookiesPreference cookies_preference_;

  // Owns the contained requests.
  std::set<URLRequest*> inflight_requests_;

  // Called when a sent report results in an error.
  ErrorCallback error_callback_;

  DISALLOW_COPY_AND_ASSIGN(ReportSender);
};

}  // namespace net

#endif  // NET_URL_REQUEST_REPORT_SENDER_H_

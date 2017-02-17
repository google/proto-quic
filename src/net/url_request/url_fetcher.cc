// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_fetcher.h"

#include "net/url_request/url_fetcher_factory.h"
#include "net/url_request/url_fetcher_impl.h"

namespace net {

URLFetcher::~URLFetcher() {}

// static
std::unique_ptr<URLFetcher> URLFetcher::Create(
    const GURL& url,
    URLFetcher::RequestType request_type,
    URLFetcherDelegate* d) {
  return URLFetcher::Create(0, url, request_type, d);
}

// static
std::unique_ptr<URLFetcher> URLFetcher::Create(
    int id,
    const GURL& url,
    URLFetcher::RequestType request_type,
    URLFetcherDelegate* d) {
  URLFetcherFactory* factory = URLFetcherImpl::factory();
  return factory ? factory->CreateURLFetcher(id, url, request_type, d)
                 : std::unique_ptr<URLFetcher>(
                       new URLFetcherImpl(url, request_type, d));
}

// static
std::unique_ptr<URLFetcher> URLFetcher::Create(
    const GURL& url,
    URLFetcher::RequestType request_type,
    URLFetcherDelegate* d,
    NetworkTrafficAnnotationTag traffic_annotation) {
  return URLFetcher::Create(0, url, request_type, d, traffic_annotation);
}

// static
std::unique_ptr<URLFetcher> URLFetcher::Create(
    int id,
    const GURL& url,
    URLFetcher::RequestType request_type,
    URLFetcherDelegate* d,
    NetworkTrafficAnnotationTag traffic_annotation) {
  // traffic_annotation is just a tag that is extracted during static
  // code analysis and can be ignored here.
  return Create(id, url, request_type, d);
}

// static
void URLFetcher::CancelAll() {
  URLFetcherImpl::CancelAll();
}

// static
void URLFetcher::SetIgnoreCertificateRequests(bool ignored) {
  URLFetcherImpl::SetIgnoreCertificateRequests(ignored);
}

}  // namespace net

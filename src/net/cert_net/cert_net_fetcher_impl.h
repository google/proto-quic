// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_NET_CERT_NET_FETCHER_H_
#define NET_CERT_NET_CERT_NET_FETCHER_H_

#include <memory>

#include "net/base/net_export.h"

namespace net {

class CertNetFetcher;
class URLRequestContextGetter;

// Creates a CertNetFetcher that issues requests through the provided
// URLRequestContext.
//
// The returned CertNetFetcher is to be operated on a thread *other* than the
// thread used for the URLRequestContext (since it gives a blocking interface
// to URL fetching).
NET_EXPORT std::unique_ptr<CertNetFetcher> CreateCertNetFetcher(
    URLRequestContextGetter* context_getter);

}  // namespace net

#endif  // NET_CERT_NET_CERT_NET_FETCHER_H_

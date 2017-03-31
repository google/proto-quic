// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_REPORTING_REPORTING_TEST_UTIL_H_
#define NET_REPORTING_REPORTING_TEST_UTIL_H_

class GURL;

namespace url {
class Origin;
}  // namespace url

namespace net {

class ReportingCache;
struct ReportingClient;

// Finds a particular client (by origin and endpoint) in the cache and returns
// it (or nullptr if not found).
const ReportingClient* FindClientInCache(const ReportingCache* cache,
                                         const url::Origin& origin,
                                         const GURL& endpoint);

}  // namespace net

#endif  // NET_REPORING_REPORTING_TEST_UTIL_H_

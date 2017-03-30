// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_test_util.h"

#include <vector>

#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_client.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {

const ReportingClient* FindClientInCache(const ReportingCache* cache,
                                         const url::Origin& origin,
                                         const GURL& endpoint) {
  std::vector<const ReportingClient*> clients;
  cache->GetClients(&clients);
  for (const ReportingClient* client : clients) {
    if (client->origin == origin && client->endpoint == endpoint)
      return client;
  }
  return nullptr;
}

}  // namespace net

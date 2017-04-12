// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_endpoint_manager.h"

#include <string>
#include <vector>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/rand_util.h"
#include "base/stl_util.h"
#include "base/time/tick_clock.h"
#include "net/base/backoff_entry.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_client.h"
#include "net/reporting/reporting_policy.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {

ReportingEndpointManager::ReportingEndpointManager(ReportingContext* context)
    : context_(context) {}

ReportingEndpointManager::~ReportingEndpointManager() {}

bool ReportingEndpointManager::FindEndpointForOriginAndGroup(
    const url::Origin& origin,
    const std::string& group,
    GURL* endpoint_url_out) {
  std::vector<const ReportingClient*> clients;
  cache()->GetClientsForOriginAndGroup(origin, group, &clients);

  // Filter out expired, pending, and backed-off endpoints.
  std::vector<const ReportingClient*> available_clients;
  base::TimeTicks now = tick_clock()->NowTicks();
  for (const ReportingClient* client : clients) {
    if (client->expires < now)
      continue;
    if (base::ContainsKey(pending_endpoints_, client->endpoint))
      continue;
    if (base::ContainsKey(endpoint_backoff_, client->endpoint) &&
        endpoint_backoff_[client->endpoint]->ShouldRejectRequest()) {
      continue;
    }
    available_clients.push_back(client);
  }

  if (available_clients.empty()) {
    *endpoint_url_out = GURL();
    return false;
  }

  int random_index = base::RandInt(0, available_clients.size() - 1);
  *endpoint_url_out = available_clients[random_index]->endpoint;
  return true;
}

void ReportingEndpointManager::SetEndpointPending(const GURL& endpoint) {
  DCHECK(!base::ContainsKey(pending_endpoints_, endpoint));
  pending_endpoints_.insert(endpoint);
}

void ReportingEndpointManager::ClearEndpointPending(const GURL& endpoint) {
  DCHECK(base::ContainsKey(pending_endpoints_, endpoint));
  pending_endpoints_.erase(endpoint);
}

void ReportingEndpointManager::InformOfEndpointRequest(const GURL& endpoint,
                                                       bool succeeded) {
  if (!base::ContainsKey(endpoint_backoff_, endpoint)) {
    endpoint_backoff_[endpoint] = base::MakeUnique<BackoffEntry>(
        &policy().endpoint_backoff_policy, tick_clock());
  }
  endpoint_backoff_[endpoint]->InformOfRequest(succeeded);
}

}  // namespace net

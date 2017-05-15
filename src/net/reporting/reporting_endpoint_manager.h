// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_REPORTING_REPORTING_ENDPOINT_MANAGER_H_
#define NET_REPORTING_REPORTING_ENDPOINT_MANAGER_H_

#include <map>
#include <memory>
#include <set>
#include <string>

#include "base/macros.h"
#include "base/time/tick_clock.h"
#include "net/base/backoff_entry.h"
#include "net/base/net_export.h"
#include "net/reporting/reporting_context.h"

class GURL;

namespace base {
class TickClock;
}  // namespace base

namespace url {
class Origin;
}  // namespace url

namespace net {

class ReportingCache;
struct ReportingPolicy;

// Keeps track of which endpoints are pending (have active delivery attempts to
// them) or in exponential backoff after one or more failures, and chooses an
// endpoint from an endpoint group to receive reports for an origin.
class NET_EXPORT ReportingEndpointManager {
 public:
  // |context| must outlive the ReportingEndpointManager.
  ReportingEndpointManager(ReportingContext* context);
  ~ReportingEndpointManager();

  // Finds an endpoint configured by |origin| in group |group| that is not
  // pending, in exponential backoff from failed requests, or expired.
  //
  // Deliberately chooses an endpoint randomly to ensure sites aren't relying on
  // any sort of fallback ordering.
  //
  // Returns true and sets |*endpoint_url_out| to the endpoint URL if an
  // endpoint was chosen; returns false (and leaves |*endpoint_url_out| invalid)
  // if no endpoint was found.
  bool FindEndpointForOriginAndGroup(const url::Origin& origin,
                                     const std::string& group,
                                     GURL* endpoint_url_out);

  // Adds |endpoint| to the set of pending endpoints, preventing it from being
  // chosen for a second parallel delivery attempt.
  void SetEndpointPending(const GURL& endpoint);

  // Removes |endpoint| from the set of pending endpoints.
  void ClearEndpointPending(const GURL& endpoint);

  // Informs the EndpointManager of a successful or unsuccessful request made to
  // |endpoint| so it can manage exponential backoff of failing endpoints.
  void InformOfEndpointRequest(const GURL& endpoint, bool succeeded);

 private:
  const ReportingPolicy& policy() { return context_->policy(); }
  base::TickClock* tick_clock() { return context_->tick_clock(); }
  ReportingCache* cache() { return context_->cache(); }

  ReportingContext* context_;

  std::set<GURL> pending_endpoints_;

  // Note: Currently the ReportingBrowsingDataRemover does not clear this data
  // because it's not persisted to disk. If it's ever persisted, it will need
  // to be cleared as well.
  std::map<GURL, std::unique_ptr<net::BackoffEntry>> endpoint_backoff_;

  DISALLOW_COPY_AND_ASSIGN(ReportingEndpointManager);
};

}  // namespace net

#endif  // NET_REPORTING_REPORTING_ENDPOINT_MANAGER_H_

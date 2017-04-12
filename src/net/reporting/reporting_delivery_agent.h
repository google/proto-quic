// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_REPORTING_REPORTING_DELIVERY_AGENT_H_
#define NET_REPORTING_REPORTING_DELIVERY_AGENT_H_

#include <memory>
#include <set>
#include <string>
#include <utility>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "net/base/backoff_entry.h"
#include "net/base/net_export.h"
#include "net/reporting/reporting_context.h"
#include "net/reporting/reporting_uploader.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace base {
class TickClock;
}  // namespace base

namespace net {

class ReportingCache;
class ReportingEndpointManager;

// Takes reports from the ReportingCache, assembles reports into deliveries to
// endpoints, and sends those deliveries using ReportingUploader.
//
// Since the Reporting spec is completely silent on issues of concurrency, the
// delivery agent handles it as so:
//
// 1. An individual report can only be included in one delivery at once -- if
//    SendReports is called again while a report is being delivered, it won't
//    be included in another delivery during that call to SendReports. (This is,
//    in fact, made redundant by rule 3, but it's included anyway in case rule 3
//    changes.)
//
// 2. An endpoint can only be the target of one delivery at once -- if
//    SendReports is called again with reports that could be delivered to that
//    endpoint, they won't be delivered to that endpoint.
//
// 3. Reports for an (origin, group) tuple can only be included in one delivery
//    at once -- if SendReports is called again with reports in that (origin,
//    group), they won't be included in any delivery during that call to
//    SendReports. (This prevents the agent from getting around rule 2 by using
//    other endpoints in the same group.)
//
// 4. Reports for the same origin *can* be included in multiple parallel
//    deliveries if they are in different groups within that origin.
//
// (Note that a single delivery can contain an infinite number of reports.)
//
// TODO(juliatuttle): Consider capping the maximum number of reports per
// delivery attempt.
class NET_EXPORT ReportingDeliveryAgent {
 public:
  // |context| must outlive the ReportingDeliveryAgent.
  ReportingDeliveryAgent(ReportingContext* context);
  ~ReportingDeliveryAgent();

  // Tries to deliver all of the reports in the cache. Reports that are already
  // being delivered will not be attempted a second time, and reports that do
  // not have a viable endpoint will be neither attempted nor removed.
  void SendReports();

 private:
  class Delivery;

  using OriginGroup = std::pair<url::Origin, std::string>;

  void OnUploadComplete(const std::unique_ptr<Delivery>& delivery,
                        ReportingUploader::Outcome outcome);

  base::TickClock* tick_clock() { return context_->tick_clock(); }
  ReportingCache* cache() { return context_->cache(); }
  ReportingUploader* uploader() { return context_->uploader(); }
  ReportingEndpointManager* endpoint_manager() {
    return context_->endpoint_manager();
  }

  ReportingContext* context_;

  // Tracks OriginGroup tuples for which there is a pending delivery running.
  // (Would be an unordered_set, but there's no hash on pair.)
  std::set<OriginGroup> pending_origin_groups_;

  base::WeakPtrFactory<ReportingDeliveryAgent> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(ReportingDeliveryAgent);
};

}  // namespace net

#endif  // NET_REPORTING_REPORTING_DELIVERY_AGENT_H_

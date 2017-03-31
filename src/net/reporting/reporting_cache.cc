// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_cache.h"

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "base/memory/ptr_util.h"
#include "base/stl_util.h"
#include "base/time/time.h"
#include "net/reporting/reporting_client.h"
#include "net/reporting/reporting_report.h"
#include "url/gurl.h"

namespace net {

ReportingCache::ReportingCache() {}

ReportingCache::~ReportingCache() {}

void ReportingCache::AddReport(const GURL& url,
                               const std::string& group,
                               const std::string& type,
                               std::unique_ptr<const base::Value> body,
                               base::TimeTicks queued,
                               int attempts) {
  auto report = base::MakeUnique<ReportingReport>(
      url, group, type, std::move(body), queued, attempts);

  auto inserted =
      reports_.insert(std::make_pair(report.get(), std::move(report)));
  DCHECK(inserted.second);
}

void ReportingCache::GetReports(
    std::vector<const ReportingReport*>* reports_out) const {
  reports_out->clear();
  for (const auto& it : reports_) {
    if (!base::ContainsKey(doomed_reports_, it.first))
      reports_out->push_back(it.second.get());
  }
}

void ReportingCache::SetReportsPending(
    const std::vector<const ReportingReport*>& reports) {
  for (const ReportingReport* report : reports) {
    auto inserted = pending_reports_.insert(report);
    DCHECK(inserted.second);
  }
}

void ReportingCache::ClearReportsPending(
    const std::vector<const ReportingReport*>& reports) {
  std::vector<const ReportingReport*> reports_to_remove;

  for (const ReportingReport* report : reports) {
    size_t erased = pending_reports_.erase(report);
    DCHECK_EQ(1u, erased);
    if (base::ContainsKey(doomed_reports_, report)) {
      reports_to_remove.push_back(report);
      doomed_reports_.erase(report);
    }
  }

  RemoveReports(reports_to_remove);
}

void ReportingCache::IncrementReportsAttempts(
    const std::vector<const ReportingReport*>& reports) {
  for (const ReportingReport* report : reports) {
    DCHECK(base::ContainsKey(reports_, report));
    reports_[report]->attempts++;
  }
}

void ReportingCache::RemoveReports(
    const std::vector<const ReportingReport*>& reports) {
  for (const ReportingReport* report : reports) {
    DCHECK(base::ContainsKey(reports_, report));
    if (base::ContainsKey(pending_reports_, report))
      doomed_reports_.insert(report);
    else {
      DCHECK(!base::ContainsKey(doomed_reports_, report));
      reports_.erase(report);
    }
  }
}

void ReportingCache::RemoveAllReports() {
  std::vector<std::unordered_map<const ReportingReport*,
                                 std::unique_ptr<ReportingReport>>::iterator>
      reports_to_remove;
  for (auto it = reports_.begin(); it != reports_.end(); ++it) {
    ReportingReport* report = it->second.get();
    if (!base::ContainsKey(pending_reports_, report))
      reports_to_remove.push_back(it);
    else
      doomed_reports_.insert(report);
  }

  for (auto& it : reports_to_remove)
    reports_.erase(it);
}

void ReportingCache::GetClients(
    std::vector<const ReportingClient*>* clients_out) const {
  clients_out->clear();
  for (const auto& it : clients_)
    for (const auto& endpoint_and_client : it.second)
      clients_out->push_back(endpoint_and_client.second.get());
}

void ReportingCache::GetClientsForOriginAndGroup(
    const url::Origin& origin,
    const std::string& group,
    std::vector<const ReportingClient*>* clients_out) const {
  clients_out->clear();

  const auto it = clients_.find(origin);
  if (it == clients_.end())
    return;

  for (const auto& endpoint_and_client : it->second) {
    if (endpoint_and_client.second->group == group)
      clients_out->push_back(endpoint_and_client.second.get());
  }
}

void ReportingCache::SetClient(const url::Origin& origin,
                               const GURL& endpoint,
                               ReportingClient::Subdomains subdomains,
                               const std::string& group,
                               base::TimeTicks expires) {
  DCHECK(endpoint.SchemeIsCryptographic());

  clients_[origin][endpoint] = base::MakeUnique<ReportingClient>(
      origin, endpoint, subdomains, group, expires);
}

void ReportingCache::RemoveClients(
    const std::vector<const ReportingClient*>& clients_to_remove) {
  for (const ReportingClient* client : clients_to_remove) {
    DCHECK(base::ContainsKey(clients_[client->origin], client->endpoint));
    DCHECK(clients_[client->origin][client->endpoint].get() == client);
    clients_[client->origin].erase(client->endpoint);
  }
}

void ReportingCache::RemoveClientForOriginAndEndpoint(const url::Origin& origin,
                                                      const GURL& endpoint) {
  DCHECK(base::ContainsKey(clients_, origin));
  DCHECK(base::ContainsKey(clients_[origin], endpoint));
  clients_[origin].erase(endpoint);
}

void ReportingCache::RemoveClientsForEndpoint(const GURL& endpoint) {
  for (auto& it : clients_)
    it.second.erase(endpoint);
}

void ReportingCache::RemoveAllClients() {
  clients_.clear();
}

}  // namespace net

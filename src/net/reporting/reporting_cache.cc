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
#include "net/reporting/reporting_context.h"
#include "net/reporting/reporting_report.h"
#include "url/gurl.h"

namespace net {

namespace {

// Returns the superdomain of a given domain, or the empty string if the given
// domain is just a single label. Note that this does not take into account
// anything like the Public Suffix List, so the superdomain may end up being a
// bare TLD.
//
// Examples:
//
// GetSuperdomain("assets.example.com") -> "example.com"
// GetSuperdomain("example.net") -> "net"
// GetSuperdomain("littlebox") -> ""
std::string GetSuperdomain(const std::string& domain) {
  size_t dot_pos = domain.find('.');
  if (dot_pos == std::string::npos)
    return "";

  return domain.substr(dot_pos + 1);
}

}  // namespace

ReportingCache::ReportingCache(ReportingContext* context) : context_(context) {
  DCHECK(context_);
}

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

  context_->NotifyCacheUpdated();
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

  context_->NotifyCacheUpdated();
}

void ReportingCache::RemoveReports(
    const std::vector<const ReportingReport*>& reports) {
  for (const ReportingReport* report : reports) {
    if (base::ContainsKey(pending_reports_, report)) {
      doomed_reports_.insert(report);
    } else {
      DCHECK(!base::ContainsKey(doomed_reports_, report));
      size_t erased = reports_.erase(report);
      DCHECK_EQ(1u, erased);
    }
  }

  context_->NotifyCacheUpdated();
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

  context_->NotifyCacheUpdated();
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
  if (it != clients_.end()) {
    for (const auto& endpoint_and_client : it->second) {
      if (endpoint_and_client.second->group == group)
        clients_out->push_back(endpoint_and_client.second.get());
    }
  }

  // If no clients were found, try successive superdomain suffixes until a
  // client with includeSubdomains is found or there are no more domain
  // components left.
  std::string domain = origin.host();
  while (clients_out->empty() && !domain.empty()) {
    GetWildcardClientsForDomainAndGroup(domain, group, clients_out);
    domain = GetSuperdomain(domain);
  }
}

void ReportingCache::SetClient(const url::Origin& origin,
                               const GURL& endpoint,
                               ReportingClient::Subdomains subdomains,
                               const std::string& group,
                               base::TimeTicks expires) {
  DCHECK(endpoint.SchemeIsCryptographic());

  // Since |subdomains| may differ from a previous call to SetClient for this
  // origin and endpoint, the cache needs to remove and re-add the client to the
  // index of wildcard clients, if applicable.
  if (base::ContainsKey(clients_, origin) &&
      base::ContainsKey(clients_[origin], endpoint)) {
    MaybeRemoveWildcardClient(clients_[origin][endpoint].get());
  }

  clients_[origin][endpoint] = base::MakeUnique<ReportingClient>(
      origin, endpoint, subdomains, group, expires);

  MaybeAddWildcardClient(clients_[origin][endpoint].get());

  context_->NotifyCacheUpdated();
}

void ReportingCache::RemoveClients(
    const std::vector<const ReportingClient*>& clients_to_remove) {
  for (const ReportingClient* client : clients_to_remove) {
    MaybeRemoveWildcardClient(client);
    size_t erased = clients_[client->origin].erase(client->endpoint);
    DCHECK_EQ(1u, erased);
  }

  context_->NotifyCacheUpdated();
}

void ReportingCache::RemoveClientForOriginAndEndpoint(const url::Origin& origin,
                                                      const GURL& endpoint) {
  MaybeRemoveWildcardClient(clients_[origin][endpoint].get());
  size_t erased = clients_[origin].erase(endpoint);
  DCHECK_EQ(1u, erased);

  context_->NotifyCacheUpdated();
}

void ReportingCache::RemoveClientsForEndpoint(const GURL& endpoint) {
  for (auto& origin_and_endpoints : clients_) {
    if (base::ContainsKey(origin_and_endpoints.second, endpoint)) {
      MaybeRemoveWildcardClient(origin_and_endpoints.second[endpoint].get());
      origin_and_endpoints.second.erase(endpoint);
    }
  }

  context_->NotifyCacheUpdated();
}

void ReportingCache::RemoveAllClients() {
  clients_.clear();
  wildcard_clients_.clear();

  context_->NotifyCacheUpdated();
}

void ReportingCache::MaybeAddWildcardClient(const ReportingClient* client) {
  if (client->subdomains != ReportingClient::Subdomains::INCLUDE)
    return;

  const std::string& domain = client->origin.host();
  auto inserted = wildcard_clients_[domain].insert(client);
  DCHECK(inserted.second);
}

void ReportingCache::MaybeRemoveWildcardClient(const ReportingClient* client) {
  if (client->subdomains != ReportingClient::Subdomains::INCLUDE)
    return;

  const std::string& domain = client->origin.host();
  size_t erased = wildcard_clients_[domain].erase(client);
  DCHECK_EQ(1u, erased);
}

void ReportingCache::GetWildcardClientsForDomainAndGroup(
    const std::string& domain,
    const std::string& group,
    std::vector<const ReportingClient*>* clients_out) const {
  clients_out->clear();

  auto it = wildcard_clients_.find(domain);
  if (it == wildcard_clients_.end())
    return;

  for (const ReportingClient* client : it->second) {
    DCHECK_EQ(ReportingClient::Subdomains::INCLUDE, client->subdomains);
    if (client->group == group)
      clients_out->push_back(client);
  }
}

}  // namespace net

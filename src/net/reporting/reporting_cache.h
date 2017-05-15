// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_REPORTING_REPORTING_CACHE_H_
#define NET_REPORTING_REPORTING_CACHE_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "base/macros.h"
#include "base/stl_util.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/net_export.h"
#include "net/reporting/reporting_client.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace base {
class TickClock;
}  // namespace base

namespace net {

class ReportingContext;
struct ReportingReport;

// The cache holds undelivered reports and clients (per-origin endpoint
// configurations) in memory. (It is not responsible for persisting them.)
//
// This corresponds roughly to the "Reporting cache" in the spec, except that
// endpoints and clients are stored in a more structurally-convenient way, and
// endpoint failures/retry-after are tracked in ReportingEndpointManager.
//
// The cache implementation has the notion of "pending" reports. These are
// reports that are part of an active delivery attempt, so they won't be
// actually deallocated. Any attempt to remove a pending report wil mark it
// "doomed", which will cause it to be deallocated once it is no longer pending.
class NET_EXPORT ReportingCache {
 public:
  // |context| must outlive the ReportingCache.
  ReportingCache(ReportingContext* context);

  ~ReportingCache();

  // Adds a report to the cache.
  //
  // All parameters correspond to the desired values for the relevant fields in
  // ReportingReport.
  void AddReport(const GURL& url,
                 const std::string& group,
                 const std::string& type,
                 std::unique_ptr<const base::Value> body,
                 base::TimeTicks queued,
                 int attempts);

  // Gets all reports in the cache. The returned pointers are valid as long as
  // either no calls to |RemoveReports| have happened or the reports' |pending|
  // flag has been set to true using |SetReportsPending|. Does not return
  // doomed reports (pending reports for which removal has been requested).
  //
  // (Clears any existing data in |*reports_out|.)
  void GetReports(std::vector<const ReportingReport*>* reports_out) const;

  // Marks a set of reports as pending. |reports| must not already be marked as
  // pending.
  void SetReportsPending(const std::vector<const ReportingReport*>& reports);

  // Unmarks a set of reports as pending. |reports| must be previously marked as
  // pending.
  void ClearReportsPending(const std::vector<const ReportingReport*>& reports);

  // Increments |attempts| on a set of reports.
  void IncrementReportsAttempts(
      const std::vector<const ReportingReport*>& reports);

  // Removes a set of reports. Any reports that are pending will not be removed
  // immediately, but rather marked doomed and removed once they are no longer
  // pending.
  void RemoveReports(const std::vector<const ReportingReport*>& reports);

  // Removes all reports. Like |RemoveReports()|, pending reports are doomed
  // until no longer pending.
  void RemoveAllReports();

  // Creates or updates a client for a particular origin and a particular
  // endpoint.
  //
  // All parameters correspond to the desired values for the fields in
  // |Client|.
  //
  // |endpoint| must use a cryptographic scheme.
  void SetClient(const url::Origin& origin,
                 const GURL& endpoint,
                 ReportingClient::Subdomains subdomains,
                 const std::string& group,
                 base::TimeTicks expires);

  void MarkClientUsed(const url::Origin& origin, const GURL& endpoint);

  // Gets all of the clients in the cache, regardless of origin or group.
  //
  // (Clears any existing data in |*clients_out|.)
  void GetClients(std::vector<const ReportingClient*>* clients_out) const;

  // Gets all of the clients configured for a particular origin in a particular
  // group. The returned pointers are only guaranteed to be valid if no calls
  // have been made to |SetClient| or |RemoveEndpoint| in between.
  //
  // If no origin match is found, the cache will return clients from the most
  // specific superdomain which contains any clients with includeSubdomains set.
  // For example, given the origin https://foo.bar.baz.com/, the cache would
  // prioritize returning each potential match below over the ones below it:
  //
  // 1. https://foo.bar.baz.com/ (exact origin match)
  // 2. https://foo.bar.baz.com:444/ (technically, a superdomain)
  // 3. https://bar.baz.com/, https://bar.baz.com:444/, etc. (superdomain)
  // 4. https://baz.com/, https://baz.com:444/, etc. (superdomain)
  // etc.
  //
  // (Clears any existing data in |*clients_out|.)
  void GetClientsForOriginAndGroup(
      const url::Origin& origin,
      const std::string& group,
      std::vector<const ReportingClient*>* clients_out) const;

  // Removes a set of clients.
  //
  // May invalidate ReportingClient pointers returned by |GetClients| or
  // |GetClientsForOriginAndGroup|.
  void RemoveClients(const std::vector<const ReportingClient*>& clients);

  // Removes a client for a particular origin and a particular endpoint.
  void RemoveClientForOriginAndEndpoint(const url::Origin& origin,
                                        const GURL& endpoint);

  // Removes all clients whose endpoint is |endpoint|.
  //
  // May invalidate ReportingClient pointers returned by |GetClients| or
  // |GetClientsForOriginAndGroup|.
  void RemoveClientsForEndpoint(const GURL& endpoint);

  // Removes all clients.
  void RemoveAllClients();

  // Gets the count of reports in the cache, *including* doomed reports.
  //
  // Needed to ensure that doomed reports are eventually deleted, since no
  // method provides a view of *every* report in the cache, just non-doomed
  // ones.
  size_t GetFullReportCountForTesting() const { return reports_.size(); }

  bool IsReportPendingForTesting(const ReportingReport* report) const {
    return base::ContainsKey(pending_reports_, report);
  }

  bool IsReportDoomedForTesting(const ReportingReport* report) const {
    return base::ContainsKey(doomed_reports_, report);
  }

 private:
  const ReportingReport* FindReportToEvict() const;

  void AddClient(std::unique_ptr<ReportingClient> client,
                 base::TimeTicks last_used);

  void RemoveClient(const ReportingClient* client);

  const ReportingClient* GetClientByOriginAndEndpoint(
      const url::Origin& origin,
      const GURL& endpoint) const;

  void GetWildcardClientsForDomainAndGroup(
      const std::string& domain,
      const std::string& group,
      std::vector<const ReportingClient*>* clients_out) const;

  const ReportingClient* FindClientToEvict(base::TimeTicks now) const;

  base::TickClock* tick_clock();

  ReportingContext* context_;

  // Owns all reports, keyed by const raw pointer for easier lookup.
  std::unordered_map<const ReportingReport*, std::unique_ptr<ReportingReport>>
      reports_;

  // Reports that have been marked pending (in use elsewhere and should not be
  // deleted until no longer pending).
  std::unordered_set<const ReportingReport*> pending_reports_;

  // Reports that have been marked doomed (would have been deleted, but were
  // pending when the deletion was requested).
  std::unordered_set<const ReportingReport*> doomed_reports_;

  // Owns all clients, keyed by origin, then endpoint URL.
  // (These would be unordered_map, but neither url::Origin nor GURL has a hash
  // function implemented.)
  std::map<url::Origin, std::map<GURL, std::unique_ptr<ReportingClient>>>
      clients_;

  // References but does not own all clients with includeSubdomains set, keyed
  // by domain name.
  std::unordered_map<std::string, std::unordered_set<const ReportingClient*>>
      wildcard_clients_;

  // The time that each client has last been used.
  std::unordered_map<const ReportingClient*, base::TimeTicks> client_last_used_;

  DISALLOW_COPY_AND_ASSIGN(ReportingCache);
};

}  // namespace net

#endif  // NET_REPORTING_REPORTING_CACHE_H_

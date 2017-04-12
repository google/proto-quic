// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_delivery_agent.h"

#include <map>
#include <string>
#include <vector>

#include "base/bind.h"
#include "base/json/json_writer.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/time/tick_clock.h"
#include "base/values.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_endpoint_manager.h"
#include "net/reporting/reporting_report.h"
#include "net/reporting/reporting_uploader.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {

namespace {

void SerializeReports(const std::vector<const ReportingReport*>& reports,
                      base::TimeTicks now,
                      std::string* json_out) {
  base::ListValue reports_value;

  for (const ReportingReport* report : reports) {
    std::unique_ptr<base::DictionaryValue> report_value =
        base::MakeUnique<base::DictionaryValue>();

    report_value->SetInteger("age", (now - report->queued).InMilliseconds());
    report_value->SetString("type", report->type);
    report_value->SetString("url", report->url.spec());
    report_value->Set("report", report->body->DeepCopy());

    reports_value.Append(std::move(report_value));
  }

  bool json_written = base::JSONWriter::Write(reports_value, json_out);
  DCHECK(json_written);
}

}  // namespace

ReportingDeliveryAgent::ReportingDeliveryAgent(ReportingContext* context)
    : context_(context), weak_factory_(this) {}
ReportingDeliveryAgent::~ReportingDeliveryAgent() {}

class ReportingDeliveryAgent::Delivery {
 public:
  Delivery(const GURL& endpoint,
           const std::vector<const ReportingReport*>& reports)
      : endpoint(endpoint), reports(reports) {}

  ~Delivery() {}

  const GURL endpoint;
  const std::vector<const ReportingReport*> reports;
};

void ReportingDeliveryAgent::SendReports() {
  std::vector<const ReportingReport*> reports;
  cache()->GetReports(&reports);

  // Sort reports into (origin, group) buckets.
  std::map<OriginGroup, std::vector<const ReportingReport*>>
      origin_group_reports;
  for (const ReportingReport* report : reports) {
    OriginGroup origin_group(url::Origin(report->url), report->group);
    origin_group_reports[origin_group].push_back(report);
  }

  // Find endpoint for each (origin, group) bucket and sort reports into
  // endpoint buckets. Don't allow concurrent deliveries to the same (origin,
  // group) bucket.
  std::map<GURL, std::vector<const ReportingReport*>> endpoint_reports;
  for (auto& it : origin_group_reports) {
    const OriginGroup& origin_group = it.first;

    if (base::ContainsKey(pending_origin_groups_, origin_group))
      continue;

    GURL endpoint_url;
    if (!endpoint_manager()->FindEndpointForOriginAndGroup(
            origin_group.first, origin_group.second, &endpoint_url)) {
      continue;
    }

    endpoint_reports[endpoint_url].insert(endpoint_reports[endpoint_url].end(),
                                          it.second.begin(), it.second.end());
    pending_origin_groups_.insert(origin_group);
  }

  // Start a delivery to each endpoint.
  for (auto& it : endpoint_reports) {
    const GURL& endpoint = it.first;
    const std::vector<const ReportingReport*>& reports = it.second;

    endpoint_manager()->SetEndpointPending(endpoint);
    cache()->SetReportsPending(reports);

    std::string json;
    SerializeReports(reports, tick_clock()->NowTicks(), &json);

    uploader()->StartUpload(
        endpoint, json,
        base::Bind(&ReportingDeliveryAgent::OnUploadComplete,
                   weak_factory_.GetWeakPtr(),
                   base::MakeUnique<Delivery>(endpoint, reports)));
  }
}

void ReportingDeliveryAgent::OnUploadComplete(
    const std::unique_ptr<Delivery>& delivery,
    ReportingUploader::Outcome outcome) {
  if (outcome == ReportingUploader::Outcome::SUCCESS) {
    cache()->RemoveReports(delivery->reports);
    endpoint_manager()->InformOfEndpointRequest(delivery->endpoint, true);
  } else {
    cache()->IncrementReportsAttempts(delivery->reports);
    endpoint_manager()->InformOfEndpointRequest(delivery->endpoint, false);
  }

  if (outcome == ReportingUploader::Outcome::REMOVE_ENDPOINT)
    cache()->RemoveClientsForEndpoint(delivery->endpoint);

  for (const ReportingReport* report : delivery->reports) {
    pending_origin_groups_.erase(
        OriginGroup(url::Origin(report->url), report->group));
  }

  endpoint_manager()->ClearEndpointPending(delivery->endpoint);
  cache()->ClearReportsPending(delivery->reports);
}

}  // namespace net

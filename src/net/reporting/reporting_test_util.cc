// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_test_util.h"

#include <memory>
#include <string>
#include <vector>

#include "base/bind.h"
#include "base/json/json_reader.h"
#include "base/memory/ptr_util.h"
#include "base/test/simple_test_clock.h"
#include "base/test/simple_test_tick_clock.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_client.h"
#include "net/reporting/reporting_context.h"
#include "net/reporting/reporting_delegate.h"
#include "net/reporting/reporting_policy.h"
#include "net/reporting/reporting_uploader.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {

namespace {

class PendingUploadImpl : public TestReportingUploader::PendingUpload {
 public:
  PendingUploadImpl(
      const GURL& url,
      const std::string& json,
      const ReportingUploader::Callback& callback,
      const base::Callback<void(PendingUpload*)>& complete_callback)
      : url_(url),
        json_(json),
        callback_(callback),
        complete_callback_(complete_callback) {}

  ~PendingUploadImpl() override {}

  // PendingUpload implementationP:
  const GURL& url() const override { return url_; }
  const std::string& json() const override { return json_; }
  std::unique_ptr<base::Value> GetValue() const override {
    return base::JSONReader::Read(json_);
  }

  void Complete(ReportingUploader::Outcome outcome) override {
    callback_.Run(outcome);
    // Deletes |this|.
    complete_callback_.Run(this);
  }

 private:
  GURL url_;
  std::string json_;
  ReportingUploader::Callback callback_;
  base::Callback<void(PendingUpload*)> complete_callback_;
};

void ErasePendingUpload(
    std::vector<std::unique_ptr<TestReportingUploader::PendingUpload>>* uploads,
    TestReportingUploader::PendingUpload* upload) {
  for (auto it = uploads->begin(); it != uploads->end(); ++it) {
    if (it->get() == upload) {
      uploads->erase(it);
      return;
    }
  }
  NOTREACHED();
}

}  // namespace

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

TestReportingDelegate::TestReportingDelegate() {}
TestReportingDelegate::~TestReportingDelegate() {}

void TestReportingDelegate::PersistData(
    std::unique_ptr<const base::Value> persisted_data) {
  persisted_data_ = std::move(persisted_data);
}

std::unique_ptr<const base::Value> TestReportingDelegate::GetPersistedData() {
  if (!persisted_data_)
    return std::unique_ptr<const base::Value>();
  return persisted_data_->CreateDeepCopy();
}

TestReportingUploader::PendingUpload::~PendingUpload() {}
TestReportingUploader::PendingUpload::PendingUpload() {}

TestReportingUploader::TestReportingUploader() {}
TestReportingUploader::~TestReportingUploader() {}

void TestReportingUploader::StartUpload(const GURL& url,
                                        const std::string& json,
                                        const Callback& callback) {
  pending_uploads_.push_back(base::MakeUnique<PendingUploadImpl>(
      url, json, callback, base::Bind(&ErasePendingUpload, &pending_uploads_)));
}

TestReportingContext::TestReportingContext(const ReportingPolicy& policy)
    : ReportingContext(policy,
                       base::MakeUnique<TestReportingDelegate>(),
                       base::MakeUnique<base::SimpleTestClock>(),
                       base::MakeUnique<base::SimpleTestTickClock>(),
                       base::MakeUnique<TestReportingUploader>()) {}

TestReportingContext::~TestReportingContext() {}

ReportingTestBase::ReportingTestBase() {
  // For tests, disable jitter.
  ReportingPolicy policy;
  policy.endpoint_backoff_policy.jitter_factor = 0.0;
  UsePolicy(policy);
}

ReportingTestBase::~ReportingTestBase() {}

void ReportingTestBase::UsePolicy(const ReportingPolicy& policy) {
  context_ = base::MakeUnique<TestReportingContext>(policy);
}

base::TimeTicks ReportingTestBase::yesterday() {
  return tick_clock()->NowTicks() - base::TimeDelta::FromDays(1);
}

base::TimeTicks ReportingTestBase::tomorrow() {
  return tick_clock()->NowTicks() + base::TimeDelta::FromDays(1);
}

}  // namespace net

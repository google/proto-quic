// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/log/trace_net_log_observer.h"

#include <stdio.h>

#include <memory>
#include <string>
#include <utility>

#include "base/json/json_writer.h"
#include "base/logging.h"
#include "base/trace_event/trace_event.h"
#include "base/values.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"

namespace net {

namespace {

// TraceLog category for NetLog events.
const char kNetLogTracingCategory[] = "netlog";

class TracedValue : public base::trace_event::ConvertableToTraceFormat {
 public:
  explicit TracedValue(std::unique_ptr<base::Value> value)
      : value_(std::move(value)) {}

 private:
  ~TracedValue() override {}

  void AppendAsTraceFormat(std::string* out) const override {
    if (value_) {
      std::string tmp;
      base::JSONWriter::Write(*value_, &tmp);
      *out += tmp;
    } else {
      *out += "\"\"";
    }
  }

 private:
  std::unique_ptr<base::Value> value_;
};

}  // namespace

TraceNetLogObserver::TraceNetLogObserver() : net_log_to_watch_(NULL) {
}

TraceNetLogObserver::~TraceNetLogObserver() {
  DCHECK(!net_log_to_watch_);
  DCHECK(!net_log());
}

void TraceNetLogObserver::OnAddEntry(const NetLog::Entry& entry) {
  std::unique_ptr<base::Value> params(entry.ParametersToValue());
  switch (entry.phase()) {
    case NetLogEventPhase::BEGIN:
      TRACE_EVENT_NESTABLE_ASYNC_BEGIN2(
          kNetLogTracingCategory, NetLog::EventTypeToString(entry.type()),
          entry.source().id, "source_type",
          NetLog::SourceTypeToString(entry.source().type), "params",
          std::unique_ptr<base::trace_event::ConvertableToTraceFormat>(
              new TracedValue(std::move(params))));
      break;
    case NetLogEventPhase::END:
      TRACE_EVENT_NESTABLE_ASYNC_END2(
          kNetLogTracingCategory, NetLog::EventTypeToString(entry.type()),
          entry.source().id, "source_type",
          NetLog::SourceTypeToString(entry.source().type), "params",
          std::unique_ptr<base::trace_event::ConvertableToTraceFormat>(
              new TracedValue(std::move(params))));
      break;
    case NetLogEventPhase::NONE:
      TRACE_EVENT_NESTABLE_ASYNC_INSTANT2(
          kNetLogTracingCategory, NetLog::EventTypeToString(entry.type()),
          entry.source().id, "source_type",
          NetLog::SourceTypeToString(entry.source().type), "params",
          std::unique_ptr<base::trace_event::ConvertableToTraceFormat>(
              new TracedValue(std::move(params))));
      break;
  }
}

void TraceNetLogObserver::WatchForTraceStart(NetLog* netlog) {
  DCHECK(!net_log_to_watch_);
  DCHECK(!net_log());
  net_log_to_watch_ = netlog;
  base::trace_event::TraceLog::GetInstance()->AddEnabledStateObserver(this);
}

void TraceNetLogObserver::StopWatchForTraceStart() {
  // Should only stop if is currently watching.
  DCHECK(net_log_to_watch_);
  base::trace_event::TraceLog::GetInstance()->RemoveEnabledStateObserver(this);
  if (net_log())
    net_log()->DeprecatedRemoveObserver(this);
  net_log_to_watch_ = NULL;
}

void TraceNetLogObserver::OnTraceLogEnabled() {
  net_log_to_watch_->DeprecatedAddObserver(this, NetLogCaptureMode::Default());
}

void TraceNetLogObserver::OnTraceLogDisabled() {
  if (net_log())
    net_log()->DeprecatedRemoveObserver(this);
}

}  // namespace net

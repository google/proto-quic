// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/log/write_to_file_net_log_observer.h"

#include <stdio.h>

#include <memory>
#include <set>
#include <utility>

#include "base/json/json_writer.h"
#include "base/logging.h"
#include "base/values.h"
#include "net/log/net_log_util.h"
#include "net/url_request/url_request_context.h"

namespace net {

WriteToFileNetLogObserver::WriteToFileNetLogObserver()
    : capture_mode_(NetLogCaptureMode::Default()), added_events_(false) {
}

WriteToFileNetLogObserver::~WriteToFileNetLogObserver() {
}

void WriteToFileNetLogObserver::set_capture_mode(
    NetLogCaptureMode capture_mode) {
  DCHECK(!net_log());
  capture_mode_ = capture_mode;
}

void WriteToFileNetLogObserver::StartObserving(
    NetLog* net_log,
    base::ScopedFILE file,
    base::Value* constants,
    URLRequestContext* url_request_context) {
  DCHECK(file.get());
  file_ = std::move(file);
  added_events_ = false;

  // Write constants to the output file.  This allows loading files that have
  // different source and event types, as they may be added and removed
  // between Chrome versions.
  std::string json;
  if (constants)
    base::JSONWriter::Write(*constants, &json);
  else
    base::JSONWriter::Write(*GetNetConstants(), &json);

  fprintf(file_.get(), "{\"constants\": %s,\n", json.c_str());

  // Start events array.  It's closed in StopObserving().
  fprintf(file_.get(), "\"events\": [\n");

  // Add events for in progress requests if a context is given.
  if (url_request_context) {
    DCHECK(url_request_context->CalledOnValidThread());

    std::set<URLRequestContext*> contexts;
    contexts.insert(url_request_context);
    CreateNetLogEntriesForActiveObjects(contexts, this);
  }

  net_log->DeprecatedAddObserver(this, capture_mode_);
}

void WriteToFileNetLogObserver::StopObserving(
    URLRequestContext* url_request_context) {
  net_log()->DeprecatedRemoveObserver(this);

  // End events array.
  fprintf(file_.get(), "]");

  // Write state of the URLRequestContext when logging stopped.
  if (url_request_context) {
    DCHECK(url_request_context->CalledOnValidThread());

    std::string json;
    base::JSONWriter::Write(
        *GetNetInfo(url_request_context, NET_INFO_ALL_SOURCES), &json);
    fprintf(file_.get(), ",\"tabInfo\": %s\n", json.c_str());
  }
  fprintf(file_.get(), "}");

  file_.reset();
}

void WriteToFileNetLogObserver::OnAddEntry(const NetLog::Entry& entry) {
  // Add a comma and newline for every event but the first.  Newlines are needed
  // so can load partial log files by just ignoring the last line.  For this to
  // work, lines cannot be pretty printed.
  std::unique_ptr<base::Value> value(entry.ToValue());
  std::string json;
  base::JSONWriter::Write(*value, &json);
  fprintf(file_.get(), "%s%s", (added_events_ ? ",\n" : ""), json.c_str());
  added_events_ = true;
}

}  // namespace net

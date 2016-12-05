// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef WRITE_TO_FILE_NET_LOG_OBSERVER_H_
#define WRITE_TO_FILE_NET_LOG_OBSERVER_H_

#include <stdio.h>

#include "base/files/scoped_file.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "net/base/net_export.h"
#include "net/log/net_log.h"

namespace base {
class Value;
}

namespace net {

class URLRequestContext;

// WriteToFileNetLogObserver watches the NetLog event stream, and sends all
// entries to a file specified on creation.
//
// The text file will contain a single JSON object.
class NET_EXPORT WriteToFileNetLogObserver : public NetLog::ThreadSafeObserver {
 public:
  WriteToFileNetLogObserver();
  ~WriteToFileNetLogObserver() override;

  // Sets the capture mode to log at. Must be called before StartObserving.
  void set_capture_mode(NetLogCaptureMode capture_mode);

  // Starts observing |net_log| and writes output to |file|.  Must not already
  // be watching a NetLog.
  //
  // |file| must be a non-NULL empty file that's open for writing.
  //
  // |constants| is an optional legend for decoding constant values used in the
  // log.  It should generally be a modified version of GetNetConstants().  If
  // not present, the output of GetNetConstants() will be used.
  //
  // |url_request_context| is an optional URLRequestContext that will be used to
  // pre-populate the log with information about in-progress events.
  // If the context is non-NULL, this must be called on the context's thread.
  void StartObserving(NetLog* net_log,
                      base::ScopedFILE file,
                      base::Value* constants,
                      URLRequestContext* url_request_context);

  // Stops observing net_log().  Must already be watching.  Must be called
  // before destruction of the WriteToFileNetLogObserver and the NetLog.
  //
  // |url_request_context| is an optional argument used to added additional
  // network stack state to the log.  If the context is non-NULL, this must be
  // called on the context's thread.
  void StopObserving(URLRequestContext* url_request_context);

  // net::NetLog::ThreadSafeObserver implementation:
  void OnAddEntry(const NetLogEntry& entry) override;

 private:
  // ----------------
  // Thread safety
  // ----------------
  //
  // NetLog observers are invoked on arbitrary threads, however are notified of
  // events in a serial fashion (the NetLog lock is held while dispatching
  // events to observers).
  //
  // As a result, the following variables do NOT need to be protected by a lock,
  // as parallel execution of OnAddEntry() is not possible.
  //
  // However any access to them outside of OnAddEntry() should be either
  // before the call to NetLog::DeprecatedAddObserver() or after the call to
  // NetLog::DeprecatedRemoveObserver().

  base::ScopedFILE file_;

  // The capture mode to log at.
  NetLogCaptureMode capture_mode_;

  // True if OnAddEntry() has been called at least once.
  bool added_events_;

  DISALLOW_COPY_AND_ASSIGN(WriteToFileNetLogObserver);
};

}  // namespace net

#endif  // WRITE_TO_FILE_NET_LOG_OBSERVER_H_

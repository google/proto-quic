// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_SYSLOG_LOGGING_H_
#define BASE_SYSLOG_LOGGING_H_

#include "base/logging.h"

namespace logging {

// Keep in mind that the syslog is always active regardless of the logging level
// and applied flags. Use only for important information that a system
// administrator might need to maintain the browser installation.
#define SYSLOG_STREAM(severity) \
  COMPACT_GOOGLE_LOG_EX_ ## severity(EventLogMessage).stream()
#define SYSLOG(severity) \
  SYSLOG_STREAM(severity)

// Creates a formatted message on the system event log. That would be the
// Application Event log on Windows and the messages log file on POSIX systems.
class BASE_EXPORT EventLogMessage {
 public:
  EventLogMessage(const char* file, int line, LogSeverity severity);

  ~EventLogMessage();

  std::ostream& stream() { return log_message_.stream(); }

 private:
  LogMessage log_message_;

  DISALLOW_COPY_AND_ASSIGN(EventLogMessage);
};

}  // namespace logging

#endif  // BASE_SYSLOG_LOGGING_H_

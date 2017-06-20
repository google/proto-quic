// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/debug/stack_trace.h"
#include "base/syslog_logging.h"

#if defined(OS_WIN)
#include "base/bind.h"
#include "base/callback_helpers.h"
#include "base/win/eventlog_messages.h"

#include <windows.h>
#elif defined(OS_LINUX)
// <syslog.h> defines a LOG_WARNING macro that could conflict with
// base::LOG_WARNING.
#include <syslog.h>
#undef LOG_WARNING
#endif

#include <cstring>
#include <ostream>
#include <string>

namespace logging {

#if defined(OS_WIN)

namespace {
std::string* g_event_source_name = nullptr;
}

void SetEventSourceName(const std::string& name) {
  DCHECK_EQ(nullptr, g_event_source_name);
  g_event_source_name = new std::string(name);
}
#endif  // defined(OS_WIN)

EventLogMessage::EventLogMessage(const char* file,
                                 int line,
                                 LogSeverity severity)
    : log_message_(file, line, severity) {
}

EventLogMessage::~EventLogMessage() {
#if defined(OS_WIN)
  // If g_event_source_name is nullptr (which it is per default) SYSLOG will
  // degrade gracefully to regular LOG. If you see this happening most probably
  // you are using SYSLOG before you called SetEventSourceName.
  if (g_event_source_name == nullptr)
    return;

  HANDLE event_log_handle =
      RegisterEventSourceA(NULL, g_event_source_name->c_str());
  if (event_log_handle == NULL) {
    stream() << " !!NOT ADDED TO EVENTLOG!!";
    return;
  }

  base::ScopedClosureRunner auto_deregister(
      base::Bind(base::IgnoreResult(&DeregisterEventSource), event_log_handle));
  std::string message(log_message_.str());
  WORD log_type = EVENTLOG_ERROR_TYPE;
  switch (log_message_.severity()) {
    case LOG_INFO:
      log_type = EVENTLOG_INFORMATION_TYPE;
      break;
    case LOG_WARNING:
      log_type = EVENTLOG_WARNING_TYPE;
      break;
    case LOG_ERROR:
    case LOG_FATAL:
      // The price of getting the stack trace is not worth the hassle for
      // non-error conditions.
      base::debug::StackTrace trace;
      message.append(trace.ToString());
      log_type = EVENTLOG_ERROR_TYPE;
      break;
  }
  LPCSTR strings[1] = {message.data()};
  if (!ReportEventA(event_log_handle, log_type, BROWSER_CATEGORY,
                    MSG_LOG_MESSAGE, NULL, 1, 0, strings, NULL)) {
    stream() << " !!NOT ADDED TO EVENTLOG!!";
  }
#elif defined(OS_LINUX)
  const char kEventSource[] = "chrome";
  openlog(kEventSource, LOG_NOWAIT | LOG_PID, LOG_USER);
  // We can't use the defined names for the logging severity from syslog.h
  // because they collide with the names of our own severity levels. Therefore
  // we use the actual values which of course do not match ours.
  // See sys/syslog.h for reference.
  int priority = 3;
  switch (log_message_.severity()) {
    case LOG_INFO:
      priority = 6;
      break;
    case LOG_WARNING:
      priority = 4;
      break;
    case LOG_ERROR:
      priority = 3;
      break;
    case LOG_FATAL:
      priority = 2;
      break;
  }
  syslog(priority, "%s", log_message_.str().c_str());
  closelog();
#endif  // defined(OS_WIN)
}

}  // namespace logging

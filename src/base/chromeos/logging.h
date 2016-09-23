// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_CHROMEOS_LOGGING_H_
#define BASE_CHROMEOS_LOGGING_H_

#include "base/logging.h"

namespace logging {

#if defined(OS_CHROMEOS)

// These macros are used to log events on ChromeOS which we want to be included
// in the system log of the device.
#define CHROMEOS_SYSLOG(severity) LOG(severity)
#define CHROMEOS_SYSLOG_IF(severity, condition) LOG_IF(severity, condition)

#else  // Not defined(OS_CHROMEOS)

#define CHROMEOS_SYSLOG(severity) LOG_IF(severity, false)
#define CHROMEOS_SYSLOG_IF(severity, condition) LOG_IF(severity, false)

#endif  // defined(OS_CHROMEOS)

}  // namespace logging

#endif  // BASE_CHROMEOS_LOGGING_H_

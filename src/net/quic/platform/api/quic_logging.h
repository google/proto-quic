// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_PLATFORM_API_QUIC_LOGGING_H_
#define NET_QUIC_PLATFORM_API_QUIC_LOGGING_H_

#include "net/quic/platform/impl/quic_logging_impl.h"

// Please note following QUIC_LOG are platform dependent:
// INFO severity can be degraded (to VLOG(1) or DVLOG(1)).
// Some platforms may not support QUIC_LOG_FIRST_N or QUIC_LOG_EVERY_N_SEC, and
// they would simply be translated to LOG.

#define QUIC_DVLOG(verbose_level) QUIC_DVLOG_IMPL(verbose_level)
#define QUIC_DLOG(severity) QUIC_DLOG_IMPL(severity)
#define QUIC_LOG(severity) QUIC_LOG_IMPL(severity)
#define QUIC_LOG_FIRST_N(severity, n) QUIC_LOG_FIRST_N_IMPL(severity, n)
#define QUIC_LOG_EVERY_N_SEC(severity, seconds) \
  QUIC_LOG_EVERY_N_SEC_IMPL(severity, seconds)
#define QUIC_LOG_IF(severity, condition) QUIC_LOG_IF_IMPL(severity, condition)

#endif  // NET_QUIC_PLATFORM_API_QUIC_LOGGING_H_

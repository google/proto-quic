// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef NET_QUIC_PLATFORM_IMPL_QUIC_BUG_TRACKER_IMPL_H_
#define NET_QUIC_PLATFORM_IMPL_QUIC_BUG_TRACKER_IMPL_H_

#include "net/quic/platform/api/quic_logging.h"

// For external QUIC, QUIC_BUG should be #defined to QUIC_LOG(DFATAL) and
// QUIC_BUG_IF(condition) to QUIC LOG_IF(DFATAL, condition) as client-side log
// rate limiting is less important and chrome doesn't QUIC_LOG_FIRST_N anyway.
#define QUIC_BUG_IMPL QUIC_LOG(DFATAL)
#define QUIC_BUG_IF_IMPL(condition) QUIC_LOG_IF(DFATAL, condition)

#endif  // NET_QUIC_PLATFORM_IMPL_QUIC_BUG_TRACKER_IMPL_H_

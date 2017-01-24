// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_EVENT_CREATOR_H_
#define NET_NQE_EVENT_CREATOR_H_

#include <stdint.h>

#include "base/time/time.h"
#include "net/nqe/effective_connection_type.h"

namespace net {

class NetLogWithSource;

namespace nqe {

namespace internal {

// Adds network quality changed event to the net-internals log. |http_rtt| is
// the estimate of the HTTP RTT. |transport_rtt| is the estimate of the
// transport RTT. |downstream_throughput_kbps| is the estimate of the
// downstream throughput (in kilobits per second). |effective_connection_type|
// is the current estimate of the effective connection type.
void AddEffectiveConnectionTypeChangedEventToNetLog(
    const NetLogWithSource& net_log,
    base::TimeDelta http_rtt,
    base::TimeDelta transport_rtt,
    int32_t downstream_throughput_kbps,
    EffectiveConnectionType effective_connection_type);

}  // namespace internal

}  // namespace nqe

}  // namespace net

#endif  // NET_NQE_EVENT_CREATOR_H_

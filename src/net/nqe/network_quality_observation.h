// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_NETWORK_QUALITY_OBSERVATION_H_
#define NET_NQE_NETWORK_QUALITY_OBSERVATION_H_

#include <vector>

#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/time/time.h"
#include "net/base/net_export.h"
#include "net/nqe/network_quality_observation_source.h"

namespace net {

namespace nqe {

namespace internal {

// Records observations of network quality metrics (such as round trip time
// or throughput), along with the time the observation was made. Observations
// can be made at several places in the network stack, thus the observation
// source is provided as well. ValueType must be numerical so that statistics
// such as median, average can be computed.
template <typename ValueType>
struct NET_EXPORT_PRIVATE Observation {
  Observation(const ValueType& value,
              base::TimeTicks timestamp,
              NetworkQualityObservationSource source)
      : value(value), timestamp(timestamp), source(source) {
    DCHECK(!timestamp.is_null());
  }
  ~Observation() {}

  // Value of the observation.
  const ValueType value;

  // Time when the observation was taken.
  const base::TimeTicks timestamp;

  // The source of the observation.
  const NetworkQualityObservationSource source;
};

}  // namespace internal

}  // namespace nqe

}  // namespace net

#endif  // NET_NQE_NETWORK_QUALITY_OBSERVATION_H_
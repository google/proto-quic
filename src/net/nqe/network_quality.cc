// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/network_quality.h"

namespace net {

namespace nqe {

namespace internal {

base::TimeDelta InvalidRTT() {
  return base::TimeDelta::Max();
}

NetworkQuality::NetworkQuality()
    : NetworkQuality(InvalidRTT(), InvalidRTT(), kInvalidThroughput) {}

NetworkQuality::NetworkQuality(const base::TimeDelta& http_rtt,
                               const base::TimeDelta& transport_rtt,
                               int32_t downstream_throughput_kbps)
    : http_rtt_(http_rtt),
      transport_rtt_(transport_rtt),
      downstream_throughput_kbps_(downstream_throughput_kbps) {
  DCHECK_GE(downstream_throughput_kbps_, 0);
}

NetworkQuality::NetworkQuality(const NetworkQuality& other)
    : NetworkQuality(other.http_rtt_,
                     other.transport_rtt_,
                     other.downstream_throughput_kbps_) {}

NetworkQuality::~NetworkQuality() {}

NetworkQuality& NetworkQuality::operator=(const NetworkQuality& other) {
  http_rtt_ = other.http_rtt_;
  transport_rtt_ = other.transport_rtt_;
  downstream_throughput_kbps_ = other.downstream_throughput_kbps_;
  return *this;
}

}  // namespace internal

}  // namespace nqe

}  // namespace net
// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_NETWORK_QUALITY_H_
#define NET_NQE_NETWORK_QUALITY_H_

#include <stdint.h>

#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/time/time.h"
#include "net/base/net_export.h"

namespace net {

namespace nqe {

namespace internal {

// Returns the RTT value to be used when the valid RTT is unavailable. Readers
// should discard RTT if it is set to the value returned by |InvalidRTT()|.
NET_EXPORT_PRIVATE base::TimeDelta InvalidRTT();

// Throughput is set to |kInvalidThroughput| if a valid value is
// unavailable. Readers should discard throughput value if it is set to
// |kInvalidThroughput|.
const int32_t kInvalidThroughput = 0;

// NetworkQuality is used to cache the quality of a network connection.
class NET_EXPORT_PRIVATE NetworkQuality {
 public:
  NetworkQuality();
  // |http_rtt| is the estimate of the round trip time at the HTTP layer.
  // |transport_rtt| is the estimate of the round trip time at the transport
  // layer. |downstream_throughput_kbps| is the estimate of the downstream
  // throughput in kilobits per second.
  NetworkQuality(const base::TimeDelta& http_rtt,
                 const base::TimeDelta& transport_rtt,
                 int32_t downstream_throughput_kbps);
  NetworkQuality(const NetworkQuality& other);
  ~NetworkQuality();

  NetworkQuality& operator=(const NetworkQuality& other);

  // Returns the estimate of the round trip time at the HTTP layer.
  const base::TimeDelta& http_rtt() const { return http_rtt_; }

  // Returns the estimate of the round trip time at the transport layer.
  const base::TimeDelta& transport_rtt() const { return transport_rtt_; }

  // Returns the estimate of the downstream throughput in Kbps (Kilobits per
  // second).
  int32_t downstream_throughput_kbps() const {
    return downstream_throughput_kbps_;
  }

 private:
  // Estimated round trip time at the HTTP layer.
  base::TimeDelta http_rtt_;

  // Estimated round trip time at the transport layer.
  base::TimeDelta transport_rtt_;

  // Estimated downstream throughput in kilobits per second.
  int32_t downstream_throughput_kbps_;
};

}  // namespace internal

}  // namespace nqe

}  // namespace net

#endif  // NET_NQE_NETWORK_QUALITY_H_
// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_EXTERNAL_ESTIMATE_PROVIDER_H_
#define NET_NQE_EXTERNAL_ESTIMATE_PROVIDER_H_

#include <stdint.h>

#include "base/macros.h"
#include "base/time/time.h"
#include "net/base/net_export.h"

namespace net {

// Base class used by external providers such as operating system APIs to
// provide network quality estimates to NetworkQualityEstimator.
class NET_EXPORT ExternalEstimateProvider {
 public:
  class NET_EXPORT UpdatedEstimateDelegate {
   public:
    // Will be called when an updated estimate is available.
    virtual void OnUpdatedEstimateAvailable() = 0;

   protected:
    UpdatedEstimateDelegate() {}
    virtual ~UpdatedEstimateDelegate() {}

   private:
    DISALLOW_COPY_AND_ASSIGN(UpdatedEstimateDelegate);
  };

  ExternalEstimateProvider() {}
  virtual ~ExternalEstimateProvider() {}

  // Returns true if the estimated RTT duration is available, and sets |rtt|
  // to the estimate.
  virtual bool GetRTT(base::TimeDelta* rtt) const = 0;

  // Returns true if the estimated downstream throughput (in Kbps -- Kilobits
  // per second) is available, and sets |downstream_throughput_kbps| to the
  // estimate.
  virtual bool GetDownstreamThroughputKbps(
      int32_t* downstream_throughput_kbps) const = 0;

  // Returns true if the estimated upstream throughput (in Kbps -- Kilobits
  // per second) is available, and sets |upstream_throughput_kbps| to the
  // estimate.
  virtual bool GetUpstreamThroughputKbps(
      int32_t* upstream_throughput_kbps) const = 0;

  // Returns true if the time since network quality was last updated is
  // available, and sets |time_since_last_update| to that value.
  virtual bool GetTimeSinceLastUpdate(
      base::TimeDelta* time_since_last_update) const = 0;

  // Sets delegate that is notified when an updated estimate is available.
  // |delegate| should outlive |ExternalEstimateProvider|.
  virtual void SetUpdatedEstimateDelegate(
      UpdatedEstimateDelegate* delegate) = 0;

  // Requests an updated network quality estimate from the external estimate
  // provider.
  virtual void Update() const = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(ExternalEstimateProvider);
};

}  // namespace net

#endif  // NET_NQE_EXTERNAL_ESTIMATE_PROVIDER_H_

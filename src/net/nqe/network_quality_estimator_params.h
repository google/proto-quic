// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_NETWORK_QUALITY_ESTIMATOR_PARAMS_H_
#define NET_NQE_NETWORK_QUALITY_ESTIMATOR_PARAMS_H_

#include <map>
#include <string>

#include "base/macros.h"
#include "base/optional.h"
#include "base/threading/thread_checker.h"
#include "net/base/net_export.h"
#include "net/base/network_change_notifier.h"
#include "net/nqe/effective_connection_type.h"
#include "net/nqe/network_quality.h"

namespace net {

// Forces NQE to return a specific effective connection type. Set using the
// |params| provided to the NetworkQualityEstimatorParams constructor.
NET_EXPORT extern const char kForceEffectiveConnectionType[];

// NetworkQualityEstimatorParams computes the configuration parameters for
// the network quality estimator.
class NET_EXPORT NetworkQualityEstimatorParams {
 public:
  // Algorithms supported by network quality estimator for computing effective
  // connection type.
  enum class EffectiveConnectionTypeAlgorithm {
    HTTP_RTT_AND_DOWNSTREAM_THROUGHOUT = 0,
    TRANSPORT_RTT_OR_DOWNSTREAM_THROUGHOUT,
    EFFECTIVE_CONNECTION_TYPE_ALGORITHM_LAST
  };

  // |params| is the map containing all field trial parameters related to
  // NetworkQualityEstimator field trial.
  explicit NetworkQualityEstimatorParams(
      const std::map<std::string, std::string>& params);

  ~NetworkQualityEstimatorParams();

  // Returns the algorithm to use for computing effective connection type. The
  // value is obtained from |params|. If the value from |params| is unavailable,
  // a default value is used.
  EffectiveConnectionTypeAlgorithm GetEffectiveConnectionTypeAlgorithm() const;

  // Returns a descriptive name corresponding to |connection_type|.
  static const char* GetNameForConnectionType(
      NetworkChangeNotifier::ConnectionType connection_type);

  // Returns the default observation for connection |type|. The default
  // observations are different for different connection types (e.g., 2G, 3G,
  // 4G, WiFi). The default observations may be used to determine the network
  // quality in absence of any other information.
  const nqe::internal::NetworkQuality& DefaultObservation(
      NetworkChangeNotifier::ConnectionType type) const;

  // Returns the typical network quality for connection |type|.
  const nqe::internal::NetworkQuality& TypicalNetworkQuality(
      EffectiveConnectionType type) const;

  // Returns the threshold for effective connection type |type|.
  const nqe::internal::NetworkQuality& ConnectionThreshold(
      EffectiveConnectionType type) const;

  // Returns the minimum number of requests in-flight to consider the network
  // fully utilized. A throughput observation is taken only when the network is
  // considered as fully utilized.
  size_t throughput_min_requests_in_flight() const {
    return throughput_min_requests_in_flight_;
  }

  // Returns the weight multiplier per second, which represents the factor by
  // which the weight of an observation reduces every second.
  double weight_multiplier_per_second() const {
    return weight_multiplier_per_second_;
  }

  // Returns the factor by which the weight of an observation reduces for every
  // dBm difference between the current signal strength (in dBm), and the signal
  // strength at the time when the observation was taken.
  double weight_multiplier_per_dbm() const {
    return weight_multiplier_per_dbm_;
  }

  // Returns the fraction of URL requests that should record the correlation
  // UMA.
  double correlation_uma_logging_probability() const {
    return correlation_uma_logging_probability_;
  }

  // Returns an unset value if the effective connection type has not been forced
  // via the |params| provided to this class. Otherwise, returns a value set to
  // the effective connection type that has been forced.
  base::Optional<EffectiveConnectionType> forced_effective_connection_type()
      const {
    return forced_effective_connection_type_;
  }

  // Returns true if reading from the persistent cache is enabled.
  bool persistent_cache_reading_enabled() const {
    return persistent_cache_reading_enabled_;
  }

  // Returns the the minimum interval betweeen consecutive notifications to a
  // single socket watcher.
  base::TimeDelta min_socket_watcher_notification_interval() const {
    return min_socket_watcher_notification_interval_;
  }

  // Returns the algorithm that should be used for computing effective
  // connection type. Returns an empty string if a valid algorithm parameter is
  // not specified.
  static EffectiveConnectionTypeAlgorithm
  GetEffectiveConnectionTypeAlgorithmFromString(
      const std::string& algorithm_param_value);

 private:
  // Map containing all field trial parameters related to
  // NetworkQualityEstimator field trial.
  const std::map<std::string, std::string> params_;

  const size_t throughput_min_requests_in_flight_;
  const double weight_multiplier_per_second_;
  const double weight_multiplier_per_dbm_;
  const double correlation_uma_logging_probability_;
  const base::Optional<EffectiveConnectionType>
      forced_effective_connection_type_;
  const bool persistent_cache_reading_enabled_;
  const base::TimeDelta min_socket_watcher_notification_interval_;

  EffectiveConnectionTypeAlgorithm effective_connection_type_algorithm_;

  // Default network quality observations obtained from |params_|.
  nqe::internal::NetworkQuality
      default_observations_[NetworkChangeNotifier::CONNECTION_LAST + 1];

  // Typical network quality for different effective connection types obtained
  // from |params_|.
  nqe::internal::NetworkQuality typical_network_quality_
      [EffectiveConnectionType::EFFECTIVE_CONNECTION_TYPE_LAST];

  // Thresholds for different effective connection types obtained from
  // |params_|. These thresholds encode how different connection types behave
  // in general.
  nqe::internal::NetworkQuality connection_thresholds_
      [EffectiveConnectionType::EFFECTIVE_CONNECTION_TYPE_LAST];

  base::ThreadChecker thread_checker_;

  DISALLOW_COPY_AND_ASSIGN(NetworkQualityEstimatorParams);
};

}  // namespace net

#endif  // NET_NQE_NETWORK_QUALITY_ESTIMATOR_PARAMS_H_

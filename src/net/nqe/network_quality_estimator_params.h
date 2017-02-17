// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_NETWORK_QUALITY_ESTIMATOR_PARAMS_H_
#define NET_NQE_NETWORK_QUALITY_ESTIMATOR_PARAMS_H_

#include <map>
#include <string>

#include "net/base/network_change_notifier.h"
#include "net/nqe/effective_connection_type.h"
#include "net/nqe/network_quality.h"

namespace net {

namespace nqe {

namespace internal {

// Returns the algorithm that should be used for computing effective connection
// type based on field trial params. Returns an empty string if a valid
// algorithm paramter is not present in the field trial params.
std::string GetEffectiveConnectionTypeAlgorithm(
    const std::map<std::string, std::string>& variation_params);

// Computes and returns the weight multiplier per second, which represents the
// factor by which the weight of an observation reduces every second.
// |variation_params| is the map containing all field trial parameters
// related to the NetworkQualityualityEstimator field trial.
double GetWeightMultiplierPerSecond(
    const std::map<std::string, std::string>& variation_params);

// Returns the factor by which the weight of an observation reduces for every
// dBm difference between the current signal strength (in dBm), and the signal
// strength at the time when the observation was taken.
double GetWeightMultiplierPerDbm(
    const std::map<std::string, std::string>& variation_params);

// Returns a descriptive name corresponding to |connection_type|.
const char* GetNameForConnectionType(
    net::NetworkChangeNotifier::ConnectionType connection_type);

// Sets the default observation for different connection types in
// |default_observations|. The default observations are different for different
// connection types (e.g., 2G, 3G, 4G, WiFi). The default observations may be
// used to determine the network quality in absence of any other information.
void ObtainDefaultObservations(
    const std::map<std::string, std::string>& variation_params,
    nqe::internal::NetworkQuality default_observations[]);

// Sets |typical_network_quality| to typical network quality for different
// effective connection types.
void ObtainTypicalNetworkQuality(NetworkQuality typical_network_quality[]);

// Parses the variation paramaters and sets the thresholds for different
// effective connection types in |connection_thresholds|.
void ObtainEffectiveConnectionTypeModelParams(
    const std::map<std::string, std::string>& variation_params,
    nqe::internal::NetworkQuality connection_thresholds[]);

// Returns the fraction of URL requests that should record the correlation UMA.
double correlation_uma_logging_probability(
    const std::map<std::string, std::string>& variation_params);

// Returns true if the effective connection type has been determined via
// variation parameters.
bool forced_effective_connection_type_set(
    const std::map<std::string, std::string>& variation_params);

// Returns the effective connection type that was configured by variation
// parameters.
EffectiveConnectionType forced_effective_connection_type(
    const std::map<std::string, std::string>& variation_params);

// Returns true if reading from the persistent cache has been enabled via field
// trial.
bool persistent_cache_reading_enabled(
    const std::map<std::string, std::string>& variation_params);

// Returns the the minimum interval betweeen consecutive notifications to a
// single socket watcher.
base::TimeDelta GetMinSocketWatcherNotificationInterval(
    const std::map<std::string, std::string>& variation_params);

}  // namespace internal

}  // namespace nqe

}  // namespace net

#endif  // NET_NQE_NETWORK_QUALITY_ESTIMATOR_PARAMS_H_

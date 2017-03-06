// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/network_quality_estimator_params.h"

#include <stdint.h>

#include "base/strings/string_number_conversions.h"
#include "base/time/time.h"

namespace {

// Minimum valid value of the variation parameter that holds RTT (in
// milliseconds) values.
static const int kMinimumRTTVariationParameterMsec = 1;

// Minimum valid value of the variation parameter that holds throughput (in
// kilobits per second) values.
static const int kMinimumThroughputVariationParameterKbps = 1;

// Returns the value of |parameter_name| read from |variation_params|. If the
// value is unavailable from |variation_params|, then |default_value| is
// returned.
int64_t GetValueForVariationParam(
    const std::map<std::string, std::string>& variation_params,
    const std::string& parameter_name,
    int64_t default_value) {
  const auto it = variation_params.find(parameter_name);
  int64_t variations_value = default_value;
  if (it != variation_params.end() &&
      base::StringToInt64(it->second, &variations_value)) {
    return variations_value;
  }
  return default_value;
}

// Returns the variation value for |parameter_name|. If the value is
// unavailable, |default_value| is returned.
double GetDoubleValueForVariationParamWithDefaultValue(
    const std::map<std::string, std::string>& variation_params,
    const std::string& parameter_name,
    double default_value) {
  const auto it = variation_params.find(parameter_name);
  if (it == variation_params.end())
    return default_value;

  double variations_value = default_value;
  if (!base::StringToDouble(it->second, &variations_value))
    return default_value;
  return variations_value;
}

// Returns the variation value for |parameter_name|. If the value is
// unavailable, |default_value| is returned.
std::string GetStringValueForVariationParamWithDefaultValue(
    const std::map<std::string, std::string>& variation_params,
    const std::string& parameter_name,
    const std::string& default_value) {
  const auto it = variation_params.find(parameter_name);
  if (it == variation_params.end())
    return default_value;
  return it->second;
}

}  // namespace

namespace net {

namespace nqe {

namespace internal {

std::string GetEffectiveConnectionTypeAlgorithm(
    const std::map<std::string, std::string>& variation_params) {
  const auto it = variation_params.find("effective_connection_type_algorithm");
  if (it == variation_params.end())
    return std::string();
  return it->second;
}

double GetWeightMultiplierPerSecond(
    const std::map<std::string, std::string>& variation_params) {
  // Default value of the half life (in seconds) for computing time weighted
  // percentiles. Every half life, the weight of all observations reduces by
  // half. Lowering the half life would reduce the weight of older values
  // faster.
  int half_life_seconds = 60;
  int32_t variations_value = 0;
  auto it = variation_params.find("HalfLifeSeconds");
  if (it != variation_params.end() &&
      base::StringToInt(it->second, &variations_value) &&
      variations_value >= 1) {
    half_life_seconds = variations_value;
  }
  DCHECK_GT(half_life_seconds, 0);
  return pow(0.5, 1.0 / half_life_seconds);
}

double GetWeightMultiplierPerDbm(
    const std::map<std::string, std::string>& variation_params) {
  // The default weight is set to 1.0, so by default, RSSI has no effect on the
  // observation's weight.
  return GetDoubleValueForVariationParamWithDefaultValue(
      variation_params, "rssi_weight_per_dbm", 1.0);
}

const char* GetNameForConnectionType(
    net::NetworkChangeNotifier::ConnectionType connection_type) {
  switch (connection_type) {
    case net::NetworkChangeNotifier::CONNECTION_UNKNOWN:
      return "Unknown";
    case net::NetworkChangeNotifier::CONNECTION_ETHERNET:
      return "Ethernet";
    case net::NetworkChangeNotifier::CONNECTION_WIFI:
      return "WiFi";
    case net::NetworkChangeNotifier::CONNECTION_2G:
      return "2G";
    case net::NetworkChangeNotifier::CONNECTION_3G:
      return "3G";
    case net::NetworkChangeNotifier::CONNECTION_4G:
      return "4G";
    case net::NetworkChangeNotifier::CONNECTION_NONE:
      return "None";
    case net::NetworkChangeNotifier::CONNECTION_BLUETOOTH:
      return "Bluetooth";
    default:
      NOTREACHED();
      break;
  }
  return "";
}

void ObtainDefaultObservations(
    const std::map<std::string, std::string>& variation_params,
    NetworkQuality default_observations[]) {
  for (size_t i = 0; i < NetworkChangeNotifier::CONNECTION_LAST; ++i) {
    DCHECK_EQ(InvalidRTT(), default_observations[i].http_rtt());
    DCHECK_EQ(InvalidRTT(), default_observations[i].transport_rtt());
    DCHECK_EQ(kInvalidThroughput,
              default_observations[i].downstream_throughput_kbps());
  }

  // Default observations for HTTP RTT, transport RTT, and downstream throughput
  // Kbps for the various connection types. These may be overridden by
  // variations params. The default observation for a connection type
  // corresponds to typical network quality for that connection type.
  default_observations[NetworkChangeNotifier::CONNECTION_UNKNOWN] =
      NetworkQuality(base::TimeDelta::FromMilliseconds(115),
                     base::TimeDelta::FromMilliseconds(55), 1961);

  default_observations[NetworkChangeNotifier::CONNECTION_ETHERNET] =
      NetworkQuality(base::TimeDelta::FromMilliseconds(90),
                     base::TimeDelta::FromMilliseconds(33), 1456);

  default_observations[NetworkChangeNotifier::CONNECTION_WIFI] =
      NetworkQuality(base::TimeDelta::FromMilliseconds(116),
                     base::TimeDelta::FromMilliseconds(66), 2658);

  default_observations[NetworkChangeNotifier::CONNECTION_2G] =
      NetworkQuality(base::TimeDelta::FromMilliseconds(1726),
                     base::TimeDelta::FromMilliseconds(1531), 74);

  default_observations[NetworkChangeNotifier::CONNECTION_3G] =
      NetworkQuality(base::TimeDelta::FromMilliseconds(272),
                     base::TimeDelta::FromMilliseconds(209), 749);

  default_observations[NetworkChangeNotifier::CONNECTION_4G] =
      NetworkQuality(base::TimeDelta::FromMilliseconds(137),
                     base::TimeDelta::FromMilliseconds(80), 1708);

  default_observations[NetworkChangeNotifier::CONNECTION_NONE] =
      NetworkQuality(base::TimeDelta::FromMilliseconds(163),
                     base::TimeDelta::FromMilliseconds(83), 575);

  default_observations[NetworkChangeNotifier::CONNECTION_BLUETOOTH] =
      NetworkQuality(base::TimeDelta::FromMilliseconds(385),
                     base::TimeDelta::FromMilliseconds(318), 476);

  // Override using the values provided via variation params.
  for (size_t i = 0; i <= NetworkChangeNotifier::CONNECTION_LAST; ++i) {
    NetworkChangeNotifier::ConnectionType type =
        static_cast<NetworkChangeNotifier::ConnectionType>(i);

    int32_t variations_value = kMinimumRTTVariationParameterMsec - 1;
    std::string parameter_name = std::string(GetNameForConnectionType(type))
                                     .append(".DefaultMedianRTTMsec");
    auto it = variation_params.find(parameter_name);
    if (it != variation_params.end() &&
        base::StringToInt(it->second, &variations_value) &&
        variations_value >= kMinimumRTTVariationParameterMsec) {
      default_observations[i] =
          NetworkQuality(base::TimeDelta::FromMilliseconds(variations_value),
                         default_observations[i].transport_rtt(),
                         default_observations[i].downstream_throughput_kbps());
    }

    variations_value = kMinimumRTTVariationParameterMsec - 1;
    parameter_name = std::string(GetNameForConnectionType(type))
                         .append(".DefaultMedianTransportRTTMsec");
    it = variation_params.find(parameter_name);
    if (it != variation_params.end() &&
        base::StringToInt(it->second, &variations_value) &&
        variations_value >= kMinimumRTTVariationParameterMsec) {
      default_observations[i] =
          NetworkQuality(default_observations[i].http_rtt(),
                         base::TimeDelta::FromMilliseconds(variations_value),
                         default_observations[i].downstream_throughput_kbps());
    }

    variations_value = kMinimumThroughputVariationParameterKbps - 1;
    parameter_name = std::string(GetNameForConnectionType(type))
                         .append(".DefaultMedianKbps");
    it = variation_params.find(parameter_name);

    if (it != variation_params.end() &&
        base::StringToInt(it->second, &variations_value) &&
        variations_value >= kMinimumThroughputVariationParameterKbps) {
      default_observations[i] = NetworkQuality(
          default_observations[i].http_rtt(),
          default_observations[i].transport_rtt(), variations_value);
    }
  }
}

void ObtainTypicalNetworkQuality(NetworkQuality typical_network_quality[]) {
  for (size_t i = 0; i < EFFECTIVE_CONNECTION_TYPE_LAST; ++i) {
    DCHECK_EQ(InvalidRTT(), typical_network_quality[i].http_rtt());
    DCHECK_EQ(InvalidRTT(), typical_network_quality[i].transport_rtt());
    DCHECK_EQ(kInvalidThroughput,
              typical_network_quality[i].downstream_throughput_kbps());
  }

  typical_network_quality[EFFECTIVE_CONNECTION_TYPE_SLOW_2G] = NetworkQuality(
      // Set to the 77.5th percentile of 2G RTT observations on Android. This
      // corresponds to the median RTT observation when effective connection
      // type is Slow 2G.
      base::TimeDelta::FromMilliseconds(3600),
      base::TimeDelta::FromMilliseconds(3000), 40);

  typical_network_quality[EFFECTIVE_CONNECTION_TYPE_2G] = NetworkQuality(
      // Set to the 58th percentile of 2G RTT observations on Android. This
      // corresponds to the median RTT observation when effective connection
      // type is 2G.
      base::TimeDelta::FromMilliseconds(1800),
      base::TimeDelta::FromMilliseconds(1500), 75);

  typical_network_quality[EFFECTIVE_CONNECTION_TYPE_3G] = NetworkQuality(
      // Set to the 75th percentile of 3G RTT observations on Android. This
      // corresponds to the median RTT observation when effective connection
      // type is 3G.
      base::TimeDelta::FromMilliseconds(450),
      base::TimeDelta::FromMilliseconds(400), 400);

  // Set to the 25th percentile of 3G RTT observations on Android.
  typical_network_quality[EFFECTIVE_CONNECTION_TYPE_4G] =
      NetworkQuality(base::TimeDelta::FromMilliseconds(175),
                     base::TimeDelta::FromMilliseconds(125), 1600);

  static_assert(
      EFFECTIVE_CONNECTION_TYPE_4G + 1 == EFFECTIVE_CONNECTION_TYPE_LAST,
      "Missing effective connection type");
}

void ObtainEffectiveConnectionTypeModelParams(
    const std::map<std::string, std::string>& variation_params,
    NetworkQuality connection_thresholds[]) {
  // First set the default thresholds.
  NetworkQuality default_effective_connection_type_thresholds
      [EffectiveConnectionType::EFFECTIVE_CONNECTION_TYPE_LAST];

  default_effective_connection_type_thresholds
      [EFFECTIVE_CONNECTION_TYPE_SLOW_2G] = NetworkQuality(
          // Set to the 66th percentile of 2G RTT observations on Android.
          base::TimeDelta::FromMilliseconds(2010),
          base::TimeDelta::FromMilliseconds(1870), kInvalidThroughput);

  default_effective_connection_type_thresholds[EFFECTIVE_CONNECTION_TYPE_2G] =
      NetworkQuality(
          // Set to the 50th percentile of RTT observations on Android.
          base::TimeDelta::FromMilliseconds(1420),
          base::TimeDelta::FromMilliseconds(1280), kInvalidThroughput);

  default_effective_connection_type_thresholds[EFFECTIVE_CONNECTION_TYPE_3G] =
      NetworkQuality(
          // Set to the 50th percentile of 3G RTT observations on Android.
          base::TimeDelta::FromMilliseconds(273),
          base::TimeDelta::FromMilliseconds(204), kInvalidThroughput);

  // Connection threshold should not be set for 4G effective connection type
  // since it is the fastest.
  static_assert(
      EFFECTIVE_CONNECTION_TYPE_3G + 1 == EFFECTIVE_CONNECTION_TYPE_4G,
      "Missing effective connection type");
  static_assert(
      EFFECTIVE_CONNECTION_TYPE_4G + 1 == EFFECTIVE_CONNECTION_TYPE_LAST,
      "Missing effective connection type");
  for (size_t i = 0; i <= EFFECTIVE_CONNECTION_TYPE_3G; ++i) {
    EffectiveConnectionType effective_connection_type =
        static_cast<EffectiveConnectionType>(i);
    DCHECK_EQ(InvalidRTT(), connection_thresholds[i].http_rtt());
    DCHECK_EQ(InvalidRTT(), connection_thresholds[i].transport_rtt());
    DCHECK_EQ(kInvalidThroughput,
              connection_thresholds[i].downstream_throughput_kbps());
    if (effective_connection_type == EFFECTIVE_CONNECTION_TYPE_UNKNOWN)
      continue;

    std::string connection_type_name = std::string(
        DeprecatedGetNameForEffectiveConnectionType(effective_connection_type));

    connection_thresholds[i].set_http_rtt(
        base::TimeDelta::FromMilliseconds(GetValueForVariationParam(
            variation_params,
            connection_type_name + ".ThresholdMedianHttpRTTMsec",
            default_effective_connection_type_thresholds[i]
                .http_rtt()
                .InMilliseconds())));

    connection_thresholds[i].set_transport_rtt(
        base::TimeDelta::FromMilliseconds(GetValueForVariationParam(
            variation_params,
            connection_type_name + ".ThresholdMedianTransportRTTMsec",
            default_effective_connection_type_thresholds[i]
                .transport_rtt()
                .InMilliseconds())));

    connection_thresholds[i].set_downstream_throughput_kbps(
        GetValueForVariationParam(
            variation_params, connection_type_name + ".ThresholdMedianKbps",
            default_effective_connection_type_thresholds[i]
                .downstream_throughput_kbps()));
    DCHECK(i == 0 ||
           connection_thresholds[i].IsFaster(connection_thresholds[i - 1]));
  }
}

double correlation_uma_logging_probability(
    const std::map<std::string, std::string>& variation_params) {
  double correlation_uma_logging_probability =
      GetDoubleValueForVariationParamWithDefaultValue(
          variation_params, "correlation_logging_probability", 0.01);
  DCHECK_LE(0.0, correlation_uma_logging_probability);
  DCHECK_GE(1.0, correlation_uma_logging_probability);
  return correlation_uma_logging_probability;
}

bool forced_effective_connection_type_set(
    const std::map<std::string, std::string>& variation_params) {
  return !GetStringValueForVariationParamWithDefaultValue(
              variation_params, "force_effective_connection_type", "")
              .empty();
}

EffectiveConnectionType forced_effective_connection_type(
    const std::map<std::string, std::string>& variation_params) {
  EffectiveConnectionType forced_effective_connection_type =
      EFFECTIVE_CONNECTION_TYPE_UNKNOWN;
  std::string forced_value = GetStringValueForVariationParamWithDefaultValue(
      variation_params, "force_effective_connection_type",
      GetNameForEffectiveConnectionType(EFFECTIVE_CONNECTION_TYPE_UNKNOWN));
  DCHECK(!forced_value.empty());
  bool effective_connection_type_available = GetEffectiveConnectionTypeForName(
      forced_value, &forced_effective_connection_type);
  DCHECK(effective_connection_type_available);

  // Silence unused variable warning in release builds.
  (void)effective_connection_type_available;

  return forced_effective_connection_type;
}

bool persistent_cache_reading_enabled(
    const std::map<std::string, std::string>& variation_params) {
  if (GetStringValueForVariationParamWithDefaultValue(
          variation_params, "persistent_cache_reading_enabled", "false") !=
      "true") {
    return false;
  }
  return true;
}

base::TimeDelta GetMinSocketWatcherNotificationInterval(
    const std::map<std::string, std::string>& variation_params) {
  // Use 1000 milliseconds as the default value.
  return base::TimeDelta::FromMilliseconds(GetValueForVariationParam(
      variation_params, "min_socket_watcher_notification_interval_msec", 1000));
}

}  // namespace internal

}  // namespace nqe

}  // namespace net

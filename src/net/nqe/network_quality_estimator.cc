// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/network_quality_estimator.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <utility>
#include <vector>

#include "base/bind_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/histogram.h"
#include "base/metrics/histogram_base.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/default_tick_clock.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "net/base/load_flags.h"
#include "net/base/load_timing_info.h"
#include "net/base/network_interfaces.h"
#include "net/base/url_util.h"
#include "net/nqe/socket_watcher_factory.h"
#include "net/nqe/throughput_analyzer.h"
#include "net/url_request/url_request.h"
#include "url/gurl.h"

#if defined(OS_ANDROID)
#include "net/android/network_library.h"
#endif  // OS_ANDROID

namespace {

// Default value of the half life (in seconds) for computing time weighted
// percentiles. Every half life, the weight of all observations reduces by
// half. Lowering the half life would reduce the weight of older values faster.
const int kDefaultHalfLifeSeconds = 60;

// Name of the variation parameter that holds the value of the half life (in
// seconds) of the observations.
const char kHalfLifeSecondsParamName[] = "HalfLifeSeconds";

// Returns a descriptive name corresponding to |connection_type|.
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

// Suffix of the name of the variation parameter that contains the default RTT
// observation (in milliseconds). Complete name of the variation parameter
// would be |ConnectionType|.|kDefaultRTTMsecObservationSuffix| where
// |ConnectionType| is from |kConnectionTypeNames|. For example, variation
// parameter for Wi-Fi would be "WiFi.DefaultMedianRTTMsec".
const char kDefaultRTTMsecObservationSuffix[] = ".DefaultMedianRTTMsec";

// Suffix of the name of the variation parameter that contains the default
// downstream throughput observation (in Kbps).  Complete name of the variation
// parameter would be |ConnectionType|.|kDefaultKbpsObservationSuffix| where
// |ConnectionType| is from |kConnectionTypeNames|. For example, variation
// parameter for Wi-Fi would be "WiFi.DefaultMedianKbps".
const char kDefaultKbpsObservationSuffix[] = ".DefaultMedianKbps";

// Suffix of the name of the variation parameter that contains the threshold
// HTTP RTTs (in milliseconds) for different effective connection types.
// Complete name of the variation parameter would be
// |EffectiveConnectionType|.|kThresholdURLRTTMsecSuffix|.
const char kThresholdURLRTTMsecSuffix[] = ".ThresholdMedianHttpRTTMsec";

// Suffix of the name of the variation parameter that contains the threshold
// downlink throughput (in kbps) for different effective connection types.
// Complete name of the variation parameter would be
// |EffectiveConnectionType|.|kThresholdKbpsSuffix|.
const char kThresholdKbpsSuffix[] = ".ThresholdMedianKbps";

// Computes and returns the weight multiplier per second.
// |variation_params| is the map containing all field trial parameters
// related to NetworkQualityEstimator field trial.
double GetWeightMultiplierPerSecond(
    const std::map<std::string, std::string>& variation_params) {
  int half_life_seconds = kDefaultHalfLifeSeconds;
  int32_t variations_value = 0;
  auto it = variation_params.find(kHalfLifeSecondsParamName);
  if (it != variation_params.end() &&
      base::StringToInt(it->second, &variations_value) &&
      variations_value >= 1) {
    half_life_seconds = variations_value;
  }
  DCHECK_GT(half_life_seconds, 0);
  return exp(log(0.5) / half_life_seconds);
}

// Returns the histogram that should be used to record the given statistic.
// |max_limit| is the maximum value that can be stored in the histogram.
base::HistogramBase* GetHistogram(
    const std::string& statistic_name,
    net::NetworkChangeNotifier::ConnectionType type,
    int32_t max_limit) {
  const base::LinearHistogram::Sample kLowerLimit = 1;
  DCHECK_GT(max_limit, kLowerLimit);
  const size_t kBucketCount = 50;

  // Prefix of network quality estimator histograms.
  const char prefix[] = "NQE.";
  return base::Histogram::FactoryGet(
      prefix + statistic_name + GetNameForConnectionType(type), kLowerLimit,
      max_limit, kBucketCount, base::HistogramBase::kUmaTargetedHistogramFlag);
}

bool GetValueForVariationParam(
    const std::map<std::string, std::string>& variation_params,
    const std::string& parameter_name,
    int32_t* variations_value) {
  const auto it = variation_params.find(parameter_name);
  return it != variation_params.end() &&
         base::StringToInt(it->second, variations_value);
}

// Returns the algorithm that should be used for computing effective connection
// type based on field trial params. Returns an empty string if a valid
// algorithm paramter is not present in the field trial params.
std::string GetEffectiveConnectionTypeAlgorithm(
    const std::map<std::string, std::string>& variation_params) {
  const auto it = variation_params.find("effective_connection_type_algorithm");
  if (it == variation_params.end())
    return std::string();
  return it->second;
}

net::NetworkQualityObservationSource ProtocolSourceToObservationSource(
    net::SocketPerformanceWatcherFactory::Protocol protocol) {
  switch (protocol) {
    case net::SocketPerformanceWatcherFactory::PROTOCOL_TCP:
      return net::NETWORK_QUALITY_OBSERVATION_SOURCE_TCP;
    case net::SocketPerformanceWatcherFactory::PROTOCOL_QUIC:
      return net::NETWORK_QUALITY_OBSERVATION_SOURCE_QUIC;
  }
  NOTREACHED();
  return net::NETWORK_QUALITY_OBSERVATION_SOURCE_TCP;
}

// Returns true if the scheme of the |request| is either HTTP or HTTPS.
bool RequestSchemeIsHTTPOrHTTPS(const net::URLRequest& request) {
  return request.url().is_valid() && request.url().SchemeIsHTTPOrHTTPS();
}

// Returns the suffix of the histogram that should be used for recording the
// accuracy when the observed RTT is |observed_rtt|. The width of the intervals
// are in exponentially increasing order.
std::string GetHistogramSuffixObservedRTT(const base::TimeDelta& observed_rtt) {
  const float rtt_milliseconds = observed_rtt.InMillisecondsF();
  DCHECK_GE(rtt_milliseconds, 0);

  // The values here should remain synchronized with the suffixes specified in
  // histograms.xml.
  static const char* const kSuffixes[] = {
      "0_20",     "20_60",     "60_140",    "140_300",      "300_620",
      "620_1260", "1260_2540", "2540_5100", "5100_Infinity"};
  for (size_t i = 0; i < arraysize(kSuffixes) - 1; ++i) {
    if (rtt_milliseconds <= static_cast<float>((20 * (2 << i) - 20)))
      return kSuffixes[i];
  }
  return kSuffixes[arraysize(kSuffixes) - 1];
}

// Returns the suffix of the histogram that should be used for recording the
// accuracy when the observed throughput in kilobits per second is
// |observed_throughput_kbps|. The width of the intervals are in exponentially
// increasing order.
std::string GetHistogramSuffixObservedThroughput(
    const int32_t& observed_throughput_kbps) {
  DCHECK_GE(observed_throughput_kbps, 0);

  // The values here should remain synchronized with the suffixes specified in
  // histograms.xml.
  static const char* const kSuffixes[] = {
      "0_20",     "20_60",     "60_140",    "140_300",      "300_620",
      "620_1260", "1260_2540", "2540_5100", "5100_Infinity"};
  for (size_t i = 0; i < arraysize(kSuffixes) - 1; ++i) {
    if (observed_throughput_kbps <= static_cast<float>((20 * (2 << i) - 20)))
      return kSuffixes[i];
  }
  return kSuffixes[arraysize(kSuffixes) - 1];
}

}  // namespace

namespace net {

NetworkQualityEstimator::NetworkQualityEstimator(
    std::unique_ptr<ExternalEstimateProvider> external_estimates_provider,
    const std::map<std::string, std::string>& variation_params)
    : NetworkQualityEstimator(std::move(external_estimates_provider),
                              variation_params,
                              false,
                              false) {}

NetworkQualityEstimator::NetworkQualityEstimator(
    std::unique_ptr<ExternalEstimateProvider> external_estimates_provider,
    const std::map<std::string, std::string>& variation_params,
    bool use_local_host_requests_for_tests,
    bool use_smaller_responses_for_tests)
    : algorithm_name_to_enum_({{"HttpRTTAndDownstreamThroughput",
                                EffectiveConnectionTypeAlgorithm::
                                    HTTP_RTT_AND_DOWNSTREAM_THROUGHOUT}}),
      use_localhost_requests_(use_local_host_requests_for_tests),
      use_small_responses_(use_smaller_responses_for_tests),
      weight_multiplier_per_second_(
          GetWeightMultiplierPerSecond(variation_params)),
      effective_connection_type_algorithm_(
          algorithm_name_to_enum_.find(GetEffectiveConnectionTypeAlgorithm(
              variation_params)) == algorithm_name_to_enum_.end()
              ? kDefaultEffectiveConnectionTypeAlgorithm
              : algorithm_name_to_enum_
                    .find(GetEffectiveConnectionTypeAlgorithm(variation_params))
                    ->second),
      tick_clock_(new base::DefaultTickClock()),
      effective_connection_type_recomputation_interval_(
          base::TimeDelta::FromSeconds(15)),
      last_connection_change_(tick_clock_->NowTicks()),
      current_network_id_(
          NetworkID(NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN,
                    std::string())),
      downstream_throughput_kbps_observations_(weight_multiplier_per_second_),
      rtt_observations_(weight_multiplier_per_second_),
      effective_connection_type_at_last_main_frame_(
          EFFECTIVE_CONNECTION_TYPE_UNKNOWN),
      external_estimate_provider_(std::move(external_estimates_provider)),
      effective_connection_type_(EFFECTIVE_CONNECTION_TYPE_UNKNOWN),
      weak_ptr_factory_(this) {
  static_assert(kDefaultHalfLifeSeconds > 0,
                "Default half life duration must be > 0");
  static_assert(kMaximumNetworkQualityCacheSize > 0,
                "Size of the network quality cache must be > 0");
  // This limit should not be increased unless the logic for removing the
  // oldest cache entry is rewritten to use a doubly-linked-list LRU queue.
  static_assert(kMaximumNetworkQualityCacheSize <= 10,
                "Size of the network quality cache must <= 10");
  // None of the algorithms can have an empty name.
  DCHECK(algorithm_name_to_enum_.end() ==
         algorithm_name_to_enum_.find(std::string()));

  DCHECK_EQ(algorithm_name_to_enum_.size(),
            static_cast<size_t>(EffectiveConnectionTypeAlgorithm::
                                    EFFECTIVE_CONNECTION_TYPE_ALGORITHM_LAST));
  DCHECK_NE(EffectiveConnectionTypeAlgorithm::
                EFFECTIVE_CONNECTION_TYPE_ALGORITHM_LAST,
            effective_connection_type_algorithm_);

  ObtainOperatingParams(variation_params);
  ObtainEffectiveConnectionTypeModelParams(variation_params);
  NetworkChangeNotifier::AddConnectionTypeObserver(this);
  if (external_estimate_provider_) {
    RecordExternalEstimateProviderMetrics(
        EXTERNAL_ESTIMATE_PROVIDER_STATUS_AVAILABLE);
    external_estimate_provider_->SetUpdatedEstimateDelegate(this);
  } else {
    RecordExternalEstimateProviderMetrics(
        EXTERNAL_ESTIMATE_PROVIDER_STATUS_NOT_AVAILABLE);
  }
  current_network_id_ = GetCurrentNetworkID();
  AddDefaultEstimates();

  throughput_analyzer_.reset(new nqe::internal::ThroughputAnalyzer(
      base::ThreadTaskRunnerHandle::Get(),
      base::Bind(&NetworkQualityEstimator::OnNewThroughputObservationAvailable,
                 base::Unretained(this)),
      use_localhost_requests_, use_smaller_responses_for_tests));

  watcher_factory_.reset(new nqe::internal::SocketWatcherFactory(
      base::ThreadTaskRunnerHandle::Get(),
      base::Bind(&NetworkQualityEstimator::OnUpdatedRTTAvailable,
                 base::Unretained(this))));

  // Record accuracy at 3 different intervals. The values used here must remain
  // in sync with the suffixes specified in
  // tools/metrics/histograms/histograms.xml.
  accuracy_recording_intervals_.push_back(base::TimeDelta::FromSeconds(15));
  accuracy_recording_intervals_.push_back(base::TimeDelta::FromSeconds(30));
  accuracy_recording_intervals_.push_back(base::TimeDelta::FromSeconds(60));
}

void NetworkQualityEstimator::ObtainOperatingParams(
    const std::map<std::string, std::string>& variation_params) {
  DCHECK(thread_checker_.CalledOnValidThread());

  for (size_t i = 0; i <= NetworkChangeNotifier::CONNECTION_LAST; ++i) {
    NetworkChangeNotifier::ConnectionType type =
        static_cast<NetworkChangeNotifier::ConnectionType>(i);
    DCHECK_EQ(nqe::internal::InvalidRTT(), default_observations_[i].http_rtt());
    DCHECK_EQ(nqe::internal::InvalidRTT(),
              default_observations_[i].transport_rtt());
    DCHECK_EQ(nqe::internal::kInvalidThroughput,
              default_observations_[i].downstream_throughput_kbps());
    int32_t variations_value = kMinimumRTTVariationParameterMsec - 1;
    // Name of the parameter that holds the RTT value for this connection type.
    std::string rtt_parameter_name =
        std::string(GetNameForConnectionType(type))
            .append(kDefaultRTTMsecObservationSuffix);
    auto it = variation_params.find(rtt_parameter_name);
    if (it != variation_params.end() &&
        base::StringToInt(it->second, &variations_value) &&
        variations_value >= kMinimumRTTVariationParameterMsec) {
      default_observations_[i] = nqe::internal::NetworkQuality(
          base::TimeDelta::FromMilliseconds(variations_value),
          default_observations_[i].transport_rtt(),
          default_observations_[i].downstream_throughput_kbps());
    }

    variations_value = kMinimumThroughputVariationParameterKbps - 1;
    // Name of the parameter that holds the Kbps value for this connection
    // type.
    std::string kbps_parameter_name =
        std::string(GetNameForConnectionType(type))
            .append(kDefaultKbpsObservationSuffix);
    it = variation_params.find(kbps_parameter_name);
    if (it != variation_params.end() &&
        base::StringToInt(it->second, &variations_value) &&
        variations_value >= kMinimumThroughputVariationParameterKbps) {
      default_observations_[i] = nqe::internal::NetworkQuality(
          default_observations_[i].http_rtt(),
          default_observations_[i].transport_rtt(), variations_value);
    }
  }
}

void NetworkQualityEstimator::ObtainEffectiveConnectionTypeModelParams(
    const std::map<std::string, std::string>& variation_params) {
  DCHECK(thread_checker_.CalledOnValidThread());

  for (size_t i = 0; i < EFFECTIVE_CONNECTION_TYPE_LAST; ++i) {
    EffectiveConnectionType effective_connection_type =
        static_cast<EffectiveConnectionType>(i);
    DCHECK_EQ(nqe::internal::InvalidRTT(),
              connection_thresholds_[i].http_rtt());
    DCHECK_EQ(nqe::internal::InvalidRTT(),
              connection_thresholds_[i].transport_rtt());
    DCHECK_EQ(nqe::internal::kInvalidThroughput,
              connection_thresholds_[i].downstream_throughput_kbps());
    if (effective_connection_type == EFFECTIVE_CONNECTION_TYPE_UNKNOWN)
      continue;

    std::string connection_type_name = std::string(
        GetNameForEffectiveConnectionType(effective_connection_type));

    int32_t variations_value = kMinimumRTTVariationParameterMsec - 1;
    if (GetValueForVariationParam(
            variation_params, connection_type_name + kThresholdURLRTTMsecSuffix,
            &variations_value) &&
        variations_value >= kMinimumRTTVariationParameterMsec) {
      base::TimeDelta rtt(base::TimeDelta::FromMilliseconds(variations_value));
      connection_thresholds_[i] = nqe::internal::NetworkQuality(
          rtt, connection_thresholds_[i].transport_rtt(),
          connection_thresholds_[i].downstream_throughput_kbps());

      // Verify that the RTT values are in decreasing order as the network
      // quality improves.
      DCHECK(i == 0 ||
             connection_thresholds_[i - 1].http_rtt() ==
                 nqe::internal::InvalidRTT() ||
             rtt <= connection_thresholds_[i - 1].http_rtt());
    }

    variations_value = kMinimumThroughputVariationParameterKbps - 1;
    if (GetValueForVariationParam(variation_params,
                                  connection_type_name + kThresholdKbpsSuffix,
                                  &variations_value) &&
        variations_value >= kMinimumThroughputVariationParameterKbps) {
      int32_t throughput_kbps = variations_value;
      connection_thresholds_[i] = nqe::internal::NetworkQuality(
          connection_thresholds_[i].http_rtt(),
          connection_thresholds_[i].transport_rtt(), throughput_kbps);

      // Verify that the throughput values are in increasing order as the
      // network quality improves.
      DCHECK(i == 0 ||
             connection_thresholds_[i - 1].downstream_throughput_kbps() ==
                 kMinimumThroughputVariationParameterKbps ||
             throughput_kbps >=
                 connection_thresholds_[i - 1].downstream_throughput_kbps());
    }
  }
}

void NetworkQualityEstimator::AddDefaultEstimates() {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (default_observations_[current_network_id_.type].http_rtt() !=
      nqe::internal::InvalidRTT()) {
    RttObservation rtt_observation(
        default_observations_[current_network_id_.type].http_rtt(),
        tick_clock_->NowTicks(),
        NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_FROM_PLATFORM);
    rtt_observations_.AddObservation(rtt_observation);
    NotifyObserversOfRTT(rtt_observation);
  }

  if (default_observations_[current_network_id_.type]
          .downstream_throughput_kbps() != nqe::internal::kInvalidThroughput) {
    ThroughputObservation throughput_observation(
        default_observations_[current_network_id_.type]
            .downstream_throughput_kbps(),
        tick_clock_->NowTicks(),
        NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_FROM_PLATFORM);
    downstream_throughput_kbps_observations_.AddObservation(
        throughput_observation);
    NotifyObserversOfThroughput(throughput_observation);
  }
}

NetworkQualityEstimator::~NetworkQualityEstimator() {
  DCHECK(thread_checker_.CalledOnValidThread());
  NetworkChangeNotifier::RemoveConnectionTypeObserver(this);
}

const std::vector<base::TimeDelta>&
NetworkQualityEstimator::GetAccuracyRecordingIntervals() const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return accuracy_recording_intervals_;
}

void NetworkQualityEstimator::NotifyStartTransaction(
    const URLRequest& request) {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!RequestSchemeIsHTTPOrHTTPS(request))
    return;

  throughput_analyzer_->NotifyStartTransaction(request);
}

void NetworkQualityEstimator::NotifyHeadersReceived(const URLRequest& request) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("net"),
               "NetworkQualityEstimator::NotifyHeadersReceived");
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!RequestSchemeIsHTTPOrHTTPS(request) ||
      !RequestProvidesRTTObservation(request)) {
    return;
  }

  const base::TimeTicks now = tick_clock_->NowTicks();

  // Update |estimated_quality_at_last_main_frame_| if this is a main frame
  // request.
  if (request.load_flags() & LOAD_MAIN_FRAME) {
    last_main_frame_request_ = now;
    base::TimeDelta estimated_http_rtt;
    if (!GetHttpRTTEstimate(&estimated_http_rtt))
      estimated_http_rtt = nqe::internal::InvalidRTT();

    base::TimeDelta estimated_transport_rtt;
    if (!GetTransportRTTEstimate(&estimated_transport_rtt))
      estimated_transport_rtt = nqe::internal::InvalidRTT();

    int32_t downstream_throughput_kbps;
    if (!GetDownlinkThroughputKbpsEstimate(&downstream_throughput_kbps))
      downstream_throughput_kbps = nqe::internal::kInvalidThroughput;

    estimated_quality_at_last_main_frame_ = nqe::internal::NetworkQuality(
        estimated_http_rtt, estimated_transport_rtt,
        downstream_throughput_kbps);
    effective_connection_type_at_last_main_frame_ =
        GetEffectiveConnectionType();

    RecordMetricsOnMainFrameRequest();

    // Post the tasks which will run in the future and record the estimation
    // accuracy based on the observations received between now and the time of
    // task execution. Posting the task at different intervals makes it
    // possible to measure the accuracy by comparing the estimate with the
    // observations received over intervals of varying durations.
    for (const base::TimeDelta& measuring_delay :
         GetAccuracyRecordingIntervals()) {
      base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
          FROM_HERE,
          base::Bind(&NetworkQualityEstimator::RecordAccuracyAfterMainFrame,
                     weak_ptr_factory_.GetWeakPtr(), measuring_delay),
          measuring_delay);
    }
  }

  LoadTimingInfo load_timing_info;
  request.GetLoadTimingInfo(&load_timing_info);

  // If the load timing info is unavailable, it probably means that the request
  // did not go over the network.
  if (load_timing_info.send_start.is_null() ||
      load_timing_info.receive_headers_end.is_null()) {
    return;
  }

  // Duration between when the resource was requested and when the response
  // headers were received.
  base::TimeDelta observed_http_rtt =
      load_timing_info.receive_headers_end - load_timing_info.send_start;
  DCHECK_GE(observed_http_rtt, base::TimeDelta());
  if (observed_http_rtt < peak_network_quality_.http_rtt()) {
    peak_network_quality_ = nqe::internal::NetworkQuality(
        observed_http_rtt, peak_network_quality_.transport_rtt(),
        peak_network_quality_.downstream_throughput_kbps());
  }

  RttObservation http_rtt_observation(
      observed_http_rtt, now, NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST);
  rtt_observations_.AddObservation(http_rtt_observation);
  NotifyObserversOfRTT(http_rtt_observation);
}

void NetworkQualityEstimator::RecordAccuracyAfterMainFrame(
    base::TimeDelta measuring_duration) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_EQ(0, measuring_duration.InMilliseconds() % 1000);
  DCHECK(ContainsValue(GetAccuracyRecordingIntervals(), measuring_duration));

  const base::TimeTicks now = tick_clock_->NowTicks();

  // Return if the time since |last_main_frame_request_| is less than
  // |measuring_duration|. This may happen if another main frame request started
  // during last |measuring_duration|. Returning here ensures that we do not
  // take inaccurate readings.
  if (now - last_main_frame_request_ < measuring_duration)
    return;

  // Return if the time since |last_main_frame_request_| is off by a factor of
  // 2. This can happen if the task is executed much later than its scheduled
  // time. Returning here ensures that we do not take inaccurate readings.
  if (now - last_main_frame_request_ > 2 * measuring_duration)
    return;

  // Do not record accuracy if there was a connection change since the last main
  // frame request.
  if (last_main_frame_request_ <= last_connection_change_)
    return;

  base::TimeDelta recent_http_rtt;
  if (estimated_quality_at_last_main_frame_.http_rtt() !=
          nqe::internal::InvalidRTT() &&
      GetRecentHttpRTTMedian(last_main_frame_request_, &recent_http_rtt)) {
    const int estimated_observed_diff_milliseconds =
        estimated_quality_at_last_main_frame_.http_rtt().InMilliseconds() -
        recent_http_rtt.InMilliseconds();

    const std::string sign_suffix =
        estimated_observed_diff_milliseconds >= 0 ? "Positive." : "Negative.";

    base::HistogramBase* histogram = base::Histogram::FactoryGet(
        "NQE.Accuracy.HttpRTT.EstimatedObservedDiff." + sign_suffix +
            base::IntToString(measuring_duration.InSeconds()) + "." +
            GetHistogramSuffixObservedRTT(recent_http_rtt),
        1, 10 * 1000 /* 10 seconds */, 50 /* Number of buckets */,
        base::HistogramBase::kUmaTargetedHistogramFlag);
    histogram->Add(std::abs(estimated_observed_diff_milliseconds));
  }

  base::TimeDelta recent_transport_rtt;
  if (estimated_quality_at_last_main_frame_.transport_rtt() !=
          nqe::internal::InvalidRTT() &&
      GetRecentTransportRTTMedian(last_main_frame_request_,
                                  &recent_transport_rtt)) {
    const int estimated_observed_diff_milliseconds =
        estimated_quality_at_last_main_frame_.transport_rtt().InMilliseconds() -
        recent_transport_rtt.InMilliseconds();

    const std::string sign_suffix =
        estimated_observed_diff_milliseconds >= 0 ? "Positive." : "Negative.";

    base::HistogramBase* histogram = base::Histogram::FactoryGet(
        "NQE.Accuracy.TransportRTT.EstimatedObservedDiff." + sign_suffix +
            base::IntToString(measuring_duration.InSeconds()) + "." +
            GetHistogramSuffixObservedRTT(recent_transport_rtt),
        1, 10 * 1000 /* 10 seconds */, 50 /* Number of buckets */,
        base::HistogramBase::kUmaTargetedHistogramFlag);
    histogram->Add(std::abs(estimated_observed_diff_milliseconds));
  }

  int32_t recent_downstream_throughput_kbps;
  if (estimated_quality_at_last_main_frame_.downstream_throughput_kbps() !=
          nqe::internal::kInvalidThroughput &&
      GetRecentMedianDownlinkThroughputKbps(
          last_main_frame_request_, &recent_downstream_throughput_kbps)) {
    const int estimated_observed_diff =
        estimated_quality_at_last_main_frame_.downstream_throughput_kbps() -
        recent_downstream_throughput_kbps;

    const std::string sign_suffix =
        estimated_observed_diff >= 0 ? "Positive." : "Negative.";

    base::HistogramBase* histogram = base::Histogram::FactoryGet(
        "NQE.Accuracy.DownstreamThroughputKbps.EstimatedObservedDiff." +
            sign_suffix + base::IntToString(measuring_duration.InSeconds()) +
            "." + GetHistogramSuffixObservedThroughput(
                      recent_downstream_throughput_kbps),
        1, 1000 * 1000 /* 1 Gbps */, 50 /* Number of buckets */,
        base::HistogramBase::kUmaTargetedHistogramFlag);
    histogram->Add(std::abs(estimated_observed_diff));
  }

  EffectiveConnectionType recent_effective_connection_type =
      GetRecentEffectiveConnectionType(last_main_frame_request_);
  if (effective_connection_type_at_last_main_frame_ !=
          EFFECTIVE_CONNECTION_TYPE_UNKNOWN &&
      recent_effective_connection_type != EFFECTIVE_CONNECTION_TYPE_UNKNOWN) {
    const int estimated_observed_diff =
        static_cast<int>(effective_connection_type_at_last_main_frame_) -
        static_cast<int>(recent_effective_connection_type);

    const std::string sign_suffix =
        estimated_observed_diff >= 0 ? "Positive." : "Negative.";

    base::HistogramBase* histogram = base::Histogram::FactoryGet(
        "NQE.Accuracy.EffectiveConnectionType.EstimatedObservedDiff." +
            sign_suffix + base::IntToString(measuring_duration.InSeconds()) +
            "." +
            GetNameForEffectiveConnectionType(recent_effective_connection_type),
        0, EFFECTIVE_CONNECTION_TYPE_LAST,
        EFFECTIVE_CONNECTION_TYPE_LAST /* Number of buckets */,
        base::HistogramBase::kUmaTargetedHistogramFlag);
    histogram->Add(std::abs(estimated_observed_diff));
  }
}

void NetworkQualityEstimator::NotifyRequestCompleted(
    const URLRequest& request) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("net"),
               "NetworkQualityEstimator::NotifyRequestCompleted");
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!RequestSchemeIsHTTPOrHTTPS(request))
    return;

  throughput_analyzer_->NotifyRequestCompleted(request);
}

void NetworkQualityEstimator::NotifyURLRequestDestroyed(
    const URLRequest& request) {
  DCHECK(thread_checker_.CalledOnValidThread());

  NotifyRequestCompleted(request);
}

void NetworkQualityEstimator::AddRTTObserver(RTTObserver* rtt_observer) {
  DCHECK(thread_checker_.CalledOnValidThread());
  rtt_observer_list_.AddObserver(rtt_observer);
}

void NetworkQualityEstimator::RemoveRTTObserver(RTTObserver* rtt_observer) {
  DCHECK(thread_checker_.CalledOnValidThread());
  rtt_observer_list_.RemoveObserver(rtt_observer);
}

void NetworkQualityEstimator::AddThroughputObserver(
    ThroughputObserver* throughput_observer) {
  DCHECK(thread_checker_.CalledOnValidThread());
  throughput_observer_list_.AddObserver(throughput_observer);
}

void NetworkQualityEstimator::RemoveThroughputObserver(
    ThroughputObserver* throughput_observer) {
  DCHECK(thread_checker_.CalledOnValidThread());
  throughput_observer_list_.RemoveObserver(throughput_observer);
}

SocketPerformanceWatcherFactory*
NetworkQualityEstimator::GetSocketPerformanceWatcherFactory() {
  DCHECK(thread_checker_.CalledOnValidThread());

  return watcher_factory_.get();
}

void NetworkQualityEstimator::SetUseLocalHostRequestsForTesting(
    bool use_localhost_requests) {
  DCHECK(thread_checker_.CalledOnValidThread());
  use_localhost_requests_ = use_localhost_requests;
  throughput_analyzer_->SetUseLocalHostRequestsForTesting(
      use_localhost_requests_);
}

void NetworkQualityEstimator::SetUseSmallResponsesForTesting(
    bool use_small_responses) {
  DCHECK(thread_checker_.CalledOnValidThread());
  use_small_responses_ = use_small_responses;
  throughput_analyzer_->SetUseSmallResponsesForTesting(use_small_responses_);
}

bool NetworkQualityEstimator::RequestProvidesRTTObservation(
    const URLRequest& request) const {
  DCHECK(thread_checker_.CalledOnValidThread());

  return (use_localhost_requests_ || !IsLocalhost(request.url().host())) &&
         // Verify that response headers are received, so it can be ensured that
         // response is not cached.
         !request.response_info().response_time.is_null() &&
         !request.was_cached() &&
         request.creation_time() >= last_connection_change_;
}

void NetworkQualityEstimator::RecordExternalEstimateProviderMetrics(
    NQEExternalEstimateProviderStatus status) const {
  UMA_HISTOGRAM_ENUMERATION("NQE.ExternalEstimateProviderStatus", status,
                            EXTERNAL_ESTIMATE_PROVIDER_STATUS_BOUNDARY);
}

void NetworkQualityEstimator::OnConnectionTypeChanged(
    NetworkChangeNotifier::ConnectionType type) {
  DCHECK(thread_checker_.CalledOnValidThread());

  RecordMetricsOnConnectionTypeChanged();

  // Write the estimates of the previous network to the cache.
  CacheNetworkQualityEstimate();

  // Clear the local state.
  last_connection_change_ = tick_clock_->NowTicks();
  peak_network_quality_ = nqe::internal::NetworkQuality();
  downstream_throughput_kbps_observations_.Clear();
  rtt_observations_.Clear();
  current_network_id_ = GetCurrentNetworkID();

  // Query the external estimate provider on certain connection types. Once the
  // updated estimates are available, OnUpdatedEstimateAvailable will be called
  // by |external_estimate_provider_| with updated estimates.
  if (external_estimate_provider_ &&
      current_network_id_.type != NetworkChangeNotifier::CONNECTION_NONE &&
      current_network_id_.type != NetworkChangeNotifier::CONNECTION_UNKNOWN &&
      current_network_id_.type != NetworkChangeNotifier::CONNECTION_ETHERNET &&
      current_network_id_.type != NetworkChangeNotifier::CONNECTION_BLUETOOTH) {
    RecordExternalEstimateProviderMetrics(
        EXTERNAL_ESTIMATE_PROVIDER_STATUS_QUERIED);
    external_estimate_provider_->Update();
  }

  // Read any cached estimates for the new network. If cached estimates are
  // unavailable, add the default estimates.
  if (!ReadCachedNetworkQualityEstimate())
    AddDefaultEstimates();
  estimated_quality_at_last_main_frame_ = nqe::internal::NetworkQuality();
  throughput_analyzer_->OnConnectionTypeChanged();
  MaybeRecomputeEffectiveConnectionType();
}

void NetworkQualityEstimator::RecordMetricsOnConnectionTypeChanged() const {
  DCHECK(thread_checker_.CalledOnValidThread());
  if (peak_network_quality_.http_rtt() != nqe::internal::InvalidRTT()) {
    base::HistogramBase* rtt_histogram =
        GetHistogram("FastestRTT.", current_network_id_.type, 10 * 1000);
    rtt_histogram->Add(peak_network_quality_.http_rtt().InMilliseconds());
  }

  if (peak_network_quality_.downstream_throughput_kbps() !=
      nqe::internal::kInvalidThroughput) {
    base::HistogramBase* downstream_throughput_histogram =
        GetHistogram("PeakKbps.", current_network_id_.type, 1000 * 1000);
    downstream_throughput_histogram->Add(
        peak_network_quality_.downstream_throughput_kbps());
  }

  base::TimeDelta rtt;
  if (GetHttpRTTEstimate(&rtt)) {
    // Add the 50th percentile value.
    base::HistogramBase* rtt_percentile =
        GetHistogram("RTT.Percentile50.", current_network_id_.type, 10 * 1000);
    rtt_percentile->Add(rtt.InMilliseconds());

    // Add the remaining percentile values.
    static const int kPercentiles[] = {0, 10, 90, 100};
    std::vector<NetworkQualityObservationSource> disallowed_observation_sources;
    disallowed_observation_sources.push_back(
        NETWORK_QUALITY_OBSERVATION_SOURCE_TCP);
    disallowed_observation_sources.push_back(
        NETWORK_QUALITY_OBSERVATION_SOURCE_QUIC);
    for (size_t i = 0; i < arraysize(kPercentiles); ++i) {
      rtt = GetRTTEstimateInternal(disallowed_observation_sources,
                                   base::TimeTicks(), kPercentiles[i]);

      rtt_percentile = GetHistogram(
          "RTT.Percentile" + base::IntToString(kPercentiles[i]) + ".",
          current_network_id_.type, 10 * 1000);  // 10 seconds
      rtt_percentile->Add(rtt.InMilliseconds());
    }
  }

  if (GetTransportRTTEstimate(&rtt)) {
    // Add the 50th percentile value.
    base::HistogramBase* transport_rtt_percentile = GetHistogram(
        "TransportRTT.Percentile50.", current_network_id_.type, 10 * 1000);
    transport_rtt_percentile->Add(rtt.InMilliseconds());

    // Add the remaining percentile values.
    static const int kPercentiles[] = {0, 10, 90, 100};
    std::vector<NetworkQualityObservationSource> disallowed_observation_sources;
    disallowed_observation_sources.push_back(
        NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST);
    // Disallow external estimate provider since it provides RTT at HTTP layer.
    disallowed_observation_sources.push_back(
        NETWORK_QUALITY_OBSERVATION_SOURCE_EXTERNAL_ESTIMATE);
    disallowed_observation_sources.push_back(
        NETWORK_QUALITY_OBSERVATION_SOURCE_CACHED_ESTIMATE);
    disallowed_observation_sources.push_back(
        NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_FROM_PLATFORM);
    for (size_t i = 0; i < arraysize(kPercentiles); ++i) {
      rtt = GetRTTEstimateInternal(disallowed_observation_sources,
                                   base::TimeTicks(), kPercentiles[i]);

      transport_rtt_percentile = GetHistogram(
          "TransportRTT.Percentile" + base::IntToString(kPercentiles[i]) + ".",
          current_network_id_.type, 10 * 1000);  // 10 seconds
      transport_rtt_percentile->Add(rtt.InMilliseconds());
    }
  }
}

void NetworkQualityEstimator::RecordMetricsOnMainFrameRequest() const {
  DCHECK(thread_checker_.CalledOnValidThread());

  base::TimeDelta http_rtt;
  if (GetHttpRTTEstimate(&http_rtt)) {
    // Add the 50th percentile value.
    base::HistogramBase* rtt_percentile = GetHistogram(
        "MainFrame.RTT.Percentile50.", current_network_id_.type, 10 * 1000);
    rtt_percentile->Add(http_rtt.InMilliseconds());
  }

  base::TimeDelta transport_rtt;
  if (GetTransportRTTEstimate(&transport_rtt)) {
    // Add the 50th percentile value.
    base::HistogramBase* transport_rtt_percentile =
        GetHistogram("MainFrame.TransportRTT.Percentile50.",
                     current_network_id_.type, 10 * 1000);
    transport_rtt_percentile->Add(transport_rtt.InMilliseconds());
  }

  int32_t kbps;
  if (GetDownlinkThroughputKbpsEstimate(&kbps)) {
    // Add the 50th percentile value.
    base::HistogramBase* throughput_percentile = GetHistogram(
        "MainFrame.Kbps.Percentile50.", current_network_id_.type, 1000 * 1000);
    throughput_percentile->Add(kbps);
  }

  const EffectiveConnectionType effective_connection_type =
      GetEffectiveConnectionType();
  base::HistogramBase* effective_connection_type_histogram =
      base::Histogram::FactoryGet(
          std::string("NQE.MainFrame.EffectiveConnectionType.") +
              GetNameForConnectionType(current_network_id_.type),
          0, EFFECTIVE_CONNECTION_TYPE_LAST,
          EFFECTIVE_CONNECTION_TYPE_LAST /* Number of buckets */,
          base::HistogramBase::kUmaTargetedHistogramFlag);

  effective_connection_type_histogram->Add(effective_connection_type);
}

NetworkQualityEstimator::EffectiveConnectionType
NetworkQualityEstimator::GetEffectiveConnectionType() const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return GetRecentEffectiveConnectionType(base::TimeTicks());
}

NetworkQualityEstimator::EffectiveConnectionType
NetworkQualityEstimator::GetRecentEffectiveConnectionType(
    const base::TimeTicks& start_time) const {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (effective_connection_type_algorithm_ ==
      EffectiveConnectionTypeAlgorithm::HTTP_RTT_AND_DOWNSTREAM_THROUGHOUT) {
    return GetRecentEffectiveConnectionTypeHttpRTTAndDownstreamThroughput(
        start_time);
  }
  // Add additional algorithms here.
  NOTREACHED();
  return EFFECTIVE_CONNECTION_TYPE_UNKNOWN;
}

NetworkQualityEstimator::EffectiveConnectionType NetworkQualityEstimator::
    GetRecentEffectiveConnectionTypeHttpRTTAndDownstreamThroughput(
        const base::TimeTicks& start_time) const {
  DCHECK(thread_checker_.CalledOnValidThread());

  // If the device is currently offline, then return
  // EFFECTIVE_CONNECTION_TYPE_OFFLINE.
  if (GetCurrentNetworkID().type == NetworkChangeNotifier::CONNECTION_NONE)
    return EFFECTIVE_CONNECTION_TYPE_OFFLINE;

  base::TimeDelta http_rtt = nqe::internal::InvalidRTT();
  if (!GetRecentHttpRTTMedian(start_time, &http_rtt))
    http_rtt = nqe::internal::InvalidRTT();

  int32_t kbps = nqe::internal::kInvalidThroughput;
  if (!GetRecentMedianDownlinkThroughputKbps(start_time, &kbps))
    kbps = nqe::internal::kInvalidThroughput;

  if (http_rtt == nqe::internal::InvalidRTT() ||
      kbps == nqe::internal::kInvalidThroughput) {
    // Quality of the current network is unknown.
    return EFFECTIVE_CONNECTION_TYPE_UNKNOWN;
  }

  // Search from the slowest connection type to the fastest to find the
  // EffectiveConnectionType that best matches the current connection's
  // performance. The match is done by comparing RTT and throughput.
  for (size_t i = 0; i < EFFECTIVE_CONNECTION_TYPE_LAST; ++i) {
    EffectiveConnectionType type = static_cast<EffectiveConnectionType>(i);
    if (i == EFFECTIVE_CONNECTION_TYPE_UNKNOWN)
      continue;
    bool estimated_http_rtt_is_higher_than_threshold =
        http_rtt != nqe::internal::InvalidRTT() &&
        connection_thresholds_[i].http_rtt() != nqe::internal::InvalidRTT() &&
        http_rtt >= connection_thresholds_[i].http_rtt();
    bool estimated_throughput_is_lower_than_threshold =
        kbps != nqe::internal::kInvalidThroughput &&
        connection_thresholds_[i].downstream_throughput_kbps() !=
            nqe::internal::kInvalidThroughput &&
        kbps <= connection_thresholds_[i].downstream_throughput_kbps();

    // Return |type| as the effective connection type if the current network's
    // RTT is worse than the threshold RTT for |type|, or if the current
    // network's throughput is lower than the threshold throughput for |type|.
    if (estimated_http_rtt_is_higher_than_threshold ||
        estimated_throughput_is_lower_than_threshold) {
      return type;
    }
  }
  // Return the fastest connection type.
  return static_cast<EffectiveConnectionType>(EFFECTIVE_CONNECTION_TYPE_LAST -
                                              1);
}

void NetworkQualityEstimator::AddEffectiveConnectionTypeObserver(
    EffectiveConnectionTypeObserver* observer) {
  DCHECK(thread_checker_.CalledOnValidThread());
  effective_connection_type_observer_list_.AddObserver(observer);
}

void NetworkQualityEstimator::RemoveEffectiveConnectionTypeObserver(
    EffectiveConnectionTypeObserver* observer) {
  DCHECK(thread_checker_.CalledOnValidThread());
  effective_connection_type_observer_list_.RemoveObserver(observer);
}

bool NetworkQualityEstimator::GetHttpRTTEstimate(base::TimeDelta* rtt) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return GetRecentHttpRTTMedian(base::TimeTicks(), rtt);
}

bool NetworkQualityEstimator::GetTransportRTTEstimate(
    base::TimeDelta* rtt) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return GetRecentTransportRTTMedian(base::TimeTicks(), rtt);
}

bool NetworkQualityEstimator::GetDownlinkThroughputKbpsEstimate(
    int32_t* kbps) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return GetRecentMedianDownlinkThroughputKbps(base::TimeTicks(), kbps);
}

bool NetworkQualityEstimator::GetRecentHttpRTTMedian(
    const base::TimeTicks& start_time,
    base::TimeDelta* rtt) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  std::vector<NetworkQualityObservationSource> disallowed_observation_sources;
  disallowed_observation_sources.push_back(
      NETWORK_QUALITY_OBSERVATION_SOURCE_TCP);
  disallowed_observation_sources.push_back(
      NETWORK_QUALITY_OBSERVATION_SOURCE_QUIC);
  *rtt = GetRTTEstimateInternal(disallowed_observation_sources, start_time, 50);
  return (*rtt != nqe::internal::InvalidRTT());
}

bool NetworkQualityEstimator::GetRecentTransportRTTMedian(
    const base::TimeTicks& start_time,
    base::TimeDelta* rtt) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  std::vector<NetworkQualityObservationSource> disallowed_observation_sources;
  disallowed_observation_sources.push_back(
      NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST);
  // Disallow external estimate provider since it provides RTT at HTTP layer.
  disallowed_observation_sources.push_back(
      NETWORK_QUALITY_OBSERVATION_SOURCE_EXTERNAL_ESTIMATE);
  disallowed_observation_sources.push_back(
      NETWORK_QUALITY_OBSERVATION_SOURCE_CACHED_ESTIMATE);
  disallowed_observation_sources.push_back(
      NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_FROM_PLATFORM);

  *rtt = GetRTTEstimateInternal(disallowed_observation_sources, start_time, 50);
  return (*rtt != nqe::internal::InvalidRTT());
}

bool NetworkQualityEstimator::GetRecentMedianDownlinkThroughputKbps(
    const base::TimeTicks& start_time,
    int32_t* kbps) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  *kbps = GetDownlinkThroughputKbpsEstimateInternal(start_time, 50);
  return (*kbps != nqe::internal::kInvalidThroughput);
}

base::TimeDelta NetworkQualityEstimator::GetRTTEstimateInternal(
    const std::vector<NetworkQualityObservationSource>&
        disallowed_observation_sources,
    const base::TimeTicks& start_time,
    int percentile) const {
  DCHECK(thread_checker_.CalledOnValidThread());

  // RTT observations are sorted by duration from shortest to longest, thus
  // a higher percentile RTT will have a longer RTT than a lower percentile.
  base::TimeDelta rtt = nqe::internal::InvalidRTT();
  if (!rtt_observations_.GetPercentile(start_time, &rtt, percentile,
                                       disallowed_observation_sources)) {
    return nqe::internal::InvalidRTT();
  }
  return rtt;
}

int32_t NetworkQualityEstimator::GetDownlinkThroughputKbpsEstimateInternal(
    const base::TimeTicks& start_time,
    int percentile) const {
  DCHECK(thread_checker_.CalledOnValidThread());

  // Throughput observations are sorted by kbps from slowest to fastest,
  // thus a higher percentile throughput will be faster than a lower one.
  int32_t kbps = nqe::internal::kInvalidThroughput;
  if (!downstream_throughput_kbps_observations_.GetPercentile(
          start_time, &kbps, 100 - percentile,
          std::vector<NetworkQualityObservationSource>())) {
    return nqe::internal::kInvalidThroughput;
  }
  return kbps;
}

NetworkQualityEstimator::NetworkID
NetworkQualityEstimator::GetCurrentNetworkID() const {
  DCHECK(thread_checker_.CalledOnValidThread());

  // TODO(tbansal): crbug.com/498068 Add NetworkQualityEstimatorAndroid class
  // that overrides this method on the Android platform.

  // It is possible that the connection type changed between when
  // GetConnectionType() was called and when the API to determine the
  // network name was called. Check if that happened and retry until the
  // connection type stabilizes. This is an imperfect solution but should
  // capture majority of cases, and should not significantly affect estimates
  // (that are approximate to begin with).
  while (true) {
    NetworkQualityEstimator::NetworkID network_id(
        NetworkChangeNotifier::GetConnectionType(), std::string());

    switch (network_id.type) {
      case NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN:
      case NetworkChangeNotifier::ConnectionType::CONNECTION_NONE:
      case NetworkChangeNotifier::ConnectionType::CONNECTION_BLUETOOTH:
      case NetworkChangeNotifier::ConnectionType::CONNECTION_ETHERNET:
        break;
      case NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI:
#if defined(OS_ANDROID) || defined(OS_LINUX) || defined(OS_CHROMEOS) || \
    defined(OS_WIN)
        network_id.id = GetWifiSSID();
#endif
        break;
      case NetworkChangeNotifier::ConnectionType::CONNECTION_2G:
      case NetworkChangeNotifier::ConnectionType::CONNECTION_3G:
      case NetworkChangeNotifier::ConnectionType::CONNECTION_4G:
#if defined(OS_ANDROID)
        network_id.id = android::GetTelephonyNetworkOperator();
#endif
        break;
      default:
        NOTREACHED() << "Unexpected connection type = " << network_id.type;
        break;
    }

    if (network_id.type == NetworkChangeNotifier::GetConnectionType())
      return network_id;
  }
  NOTREACHED();
}

bool NetworkQualityEstimator::ReadCachedNetworkQualityEstimate() {
  DCHECK(thread_checker_.CalledOnValidThread());

  // If the network name is unavailable, caching should not be performed.
  if (current_network_id_.id.empty())
    return false;

  CachedNetworkQualities::const_iterator it =
      cached_network_qualities_.find(current_network_id_);

  if (it == cached_network_qualities_.end())
    return false;

  nqe::internal::NetworkQuality network_quality(it->second.network_quality());

  const base::TimeTicks now = tick_clock_->NowTicks();
  bool read_cached_estimate = false;

  if (network_quality.downstream_throughput_kbps() !=
      nqe::internal::kInvalidThroughput) {
    read_cached_estimate = true;
    ThroughputObservation througphput_observation(
        network_quality.downstream_throughput_kbps(), now,
        NETWORK_QUALITY_OBSERVATION_SOURCE_CACHED_ESTIMATE);
    downstream_throughput_kbps_observations_.AddObservation(
        througphput_observation);
    NotifyObserversOfThroughput(througphput_observation);
  }

  if (network_quality.http_rtt() != nqe::internal::InvalidRTT()) {
    read_cached_estimate = true;
    RttObservation rtt_observation(
        network_quality.http_rtt(), now,
        NETWORK_QUALITY_OBSERVATION_SOURCE_CACHED_ESTIMATE);
    rtt_observations_.AddObservation(rtt_observation);
    NotifyObserversOfRTT(rtt_observation);
  }

  return read_cached_estimate;
}

void NetworkQualityEstimator::OnUpdatedEstimateAvailable(
    const base::TimeDelta& rtt,
    int32_t downstream_throughput_kbps,
    int32_t upstream_throughput_kbps) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(external_estimate_provider_);

  RecordExternalEstimateProviderMetrics(
      EXTERNAL_ESTIMATE_PROVIDER_STATUS_CALLBACK);

  if (rtt > base::TimeDelta()) {
    RecordExternalEstimateProviderMetrics(
        EXTERNAL_ESTIMATE_PROVIDER_STATUS_RTT_AVAILABLE);
    UMA_HISTOGRAM_TIMES("NQE.ExternalEstimateProvider.RTT", rtt);
    rtt_observations_.AddObservation(
        RttObservation(rtt, tick_clock_->NowTicks(),
                       NETWORK_QUALITY_OBSERVATION_SOURCE_EXTERNAL_ESTIMATE));
  }

  if (downstream_throughput_kbps > 0) {
    RecordExternalEstimateProviderMetrics(
        EXTERNAL_ESTIMATE_PROVIDER_STATUS_DOWNLINK_BANDWIDTH_AVAILABLE);
    UMA_HISTOGRAM_COUNTS("NQE.ExternalEstimateProvider.DownlinkBandwidth",
                         downstream_throughput_kbps);
    downstream_throughput_kbps_observations_.AddObservation(
        ThroughputObservation(
            downstream_throughput_kbps, tick_clock_->NowTicks(),
            NETWORK_QUALITY_OBSERVATION_SOURCE_EXTERNAL_ESTIMATE));
  }
}

// static
const char* NetworkQualityEstimator::GetNameForEffectiveConnectionType(
    EffectiveConnectionType type) {
  switch (type) {
    case EFFECTIVE_CONNECTION_TYPE_UNKNOWN:
      return "Unknown";
    case EFFECTIVE_CONNECTION_TYPE_OFFLINE:
      return "Offline";
    case EFFECTIVE_CONNECTION_TYPE_SLOW_2G:
      return "Slow2G";
    case EFFECTIVE_CONNECTION_TYPE_2G:
      return "2G";
    case EFFECTIVE_CONNECTION_TYPE_3G:
      return "3G";
    case EFFECTIVE_CONNECTION_TYPE_4G:
      return "4G";
    case EFFECTIVE_CONNECTION_TYPE_BROADBAND:
      return "Broadband";
    default:
      NOTREACHED();
      break;
  }
  return "";
}

// static
NetworkQualityEstimator::EffectiveConnectionType
NetworkQualityEstimator::GetEffectiveConnectionTypeForName(
    const std::string& connection_type_name) {
  if (connection_type_name == "Unknown")
    return EFFECTIVE_CONNECTION_TYPE_UNKNOWN;
  if (connection_type_name == "Offline")
    return EFFECTIVE_CONNECTION_TYPE_OFFLINE;
  if (connection_type_name == "Slow2G")
    return EFFECTIVE_CONNECTION_TYPE_SLOW_2G;
  if (connection_type_name == "2G")
    return EFFECTIVE_CONNECTION_TYPE_2G;
  if (connection_type_name == "3G")
    return EFFECTIVE_CONNECTION_TYPE_3G;
  if (connection_type_name == "4G")
    return EFFECTIVE_CONNECTION_TYPE_4G;
  if (connection_type_name == "Broadband")
    return EFFECTIVE_CONNECTION_TYPE_BROADBAND;
  NOTREACHED();
  return EFFECTIVE_CONNECTION_TYPE_UNKNOWN;
}

void NetworkQualityEstimator::SetTickClockForTesting(
    std::unique_ptr<base::TickClock> tick_clock) {
  DCHECK(thread_checker_.CalledOnValidThread());
  tick_clock_ = std::move(tick_clock);
}

void NetworkQualityEstimator::CacheNetworkQualityEstimate() {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_LE(cached_network_qualities_.size(),
            static_cast<size_t>(kMaximumNetworkQualityCacheSize));

  // If the network name is unavailable, caching should not be performed.
  if (current_network_id_.id.empty())
    return;

  base::TimeDelta http_rtt = nqe::internal::InvalidRTT();
  int32_t downlink_throughput_kbps = nqe::internal::kInvalidThroughput;

  if (!GetHttpRTTEstimate(&http_rtt) ||
      !GetDownlinkThroughputKbpsEstimate(&downlink_throughput_kbps)) {
    return;
  }

  // |transport_rtt| is currently not cached.
  nqe::internal::NetworkQuality network_quality = nqe::internal::NetworkQuality(
      http_rtt, nqe::internal::InvalidRTT() /* transport_rtt */,
      downlink_throughput_kbps);

  if (cached_network_qualities_.size() == kMaximumNetworkQualityCacheSize) {
    // Remove the oldest entry.
    CachedNetworkQualities::iterator oldest_entry_iterator =
        cached_network_qualities_.begin();

    for (CachedNetworkQualities::iterator it =
             cached_network_qualities_.begin();
         it != cached_network_qualities_.end(); ++it) {
      if ((it->second).OlderThan(oldest_entry_iterator->second))
        oldest_entry_iterator = it;
    }
    cached_network_qualities_.erase(oldest_entry_iterator);
  }
  DCHECK_LT(cached_network_qualities_.size(),
            static_cast<size_t>(kMaximumNetworkQualityCacheSize));

  cached_network_qualities_.insert(
      std::make_pair(current_network_id_,
                     nqe::internal::CachedNetworkQuality(network_quality)));
  DCHECK_LE(cached_network_qualities_.size(),
            static_cast<size_t>(kMaximumNetworkQualityCacheSize));
}

void NetworkQualityEstimator::OnUpdatedRTTAvailable(
    SocketPerformanceWatcherFactory::Protocol protocol,
    const base::TimeDelta& rtt) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_NE(nqe::internal::InvalidRTT(), rtt);

  RttObservation observation(rtt, tick_clock_->NowTicks(),
                             ProtocolSourceToObservationSource(protocol));
  NotifyObserversOfRTT(observation);
  rtt_observations_.AddObservation(observation);
}

void NetworkQualityEstimator::NotifyObserversOfRTT(
    const RttObservation& observation) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_NE(nqe::internal::InvalidRTT(), observation.value);

  // Maybe recompute the effective connection type since a new RTT observation
  // is available.
  MaybeRecomputeEffectiveConnectionType();
  FOR_EACH_OBSERVER(
      RTTObserver, rtt_observer_list_,
      OnRTTObservation(observation.value.InMilliseconds(),
                       observation.timestamp, observation.source));
}

void NetworkQualityEstimator::NotifyObserversOfThroughput(
    const ThroughputObservation& observation) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_NE(nqe::internal::kInvalidThroughput, observation.value);

  // Maybe recompute the effective connection type since a new throughput
  // observation is available.
  MaybeRecomputeEffectiveConnectionType();
  FOR_EACH_OBSERVER(
      ThroughputObserver, throughput_observer_list_,
      OnThroughputObservation(observation.value, observation.timestamp,
                              observation.source));
}

void NetworkQualityEstimator::OnNewThroughputObservationAvailable(
    int32_t downstream_kbps) {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (downstream_kbps == 0)
    return;

  DCHECK_NE(nqe::internal::kInvalidThroughput, downstream_kbps);

  if (downstream_kbps > peak_network_quality_.downstream_throughput_kbps()) {
    peak_network_quality_ = nqe::internal::NetworkQuality(
        peak_network_quality_.http_rtt(), peak_network_quality_.transport_rtt(),
        downstream_kbps);
  }
  ThroughputObservation throughput_observation(
      downstream_kbps, tick_clock_->NowTicks(),
      NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST);
  downstream_throughput_kbps_observations_.AddObservation(
      throughput_observation);
  NotifyObserversOfThroughput(throughput_observation);
}

void NetworkQualityEstimator::MaybeRecomputeEffectiveConnectionType() {
  DCHECK(thread_checker_.CalledOnValidThread());

  const base::TimeTicks now = tick_clock_->NowTicks();
  // Recompute effective connection type only if
  // |effective_connection_type_recomputation_interval_| has passed since it was
  // last computed or a connection change event was observed since the last
  // computation. Strict inequalities are used to ensure that effective
  // connection type is recomputed on connection change events even if the clock
  // has not updated.
  if (now - last_effective_connection_type_computation_ <
          effective_connection_type_recomputation_interval_ &&
      last_connection_change_ < last_effective_connection_type_computation_) {
    return;
  }

  const EffectiveConnectionType past_type = effective_connection_type_;
  last_effective_connection_type_computation_ = now;
  effective_connection_type_ = GetEffectiveConnectionType();

  if (past_type != effective_connection_type_)
    NotifyObserversOfEffectiveConnectionTypeChanged();
}

void NetworkQualityEstimator::
    NotifyObserversOfEffectiveConnectionTypeChanged() {
  DCHECK(thread_checker_.CalledOnValidThread());

  // TODO(tbansal): Add hysteresis in the notification.
  FOR_EACH_OBSERVER(
      EffectiveConnectionTypeObserver, effective_connection_type_observer_list_,
      OnEffectiveConnectionTypeChanged(effective_connection_type_));
}

}  // namespace net

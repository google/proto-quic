// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/network_quality_estimator.h"

#include <float.h>
#include <algorithm>
#include <cmath>
#include <limits>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "base/metrics/histogram.h"
#include "base/metrics/histogram_base.h"
#include "base/strings/string_number_conversions.h"
#include "base/thread_task_runner_handle.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "net/base/load_flags.h"
#include "net/base/load_timing_info.h"
#include "net/base/network_interfaces.h"
#include "net/base/socket_performance_watcher.h"
#include "net/base/url_util.h"
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
// RTTs (in milliseconds) for different effective connection types. Complete
// name of the variation parameter would be
// |EffectiveConnectionType|.|kThresholdURLRTTMsecSuffix|.
const char kThresholdURLRTTMsecSuffix[] = ".ThresholdMedianURLRTTMsec";

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
  auto it = variation_params.find(parameter_name);
  return it != variation_params.end() &&
         base::StringToInt(it->second, variations_value);
}

}  // namespace

namespace net {

// SocketWatcher implements SocketPerformanceWatcher, and notifies
// NetworkQualityEstimator of various socket performance events. SocketWatcher
// is not thread-safe.
class NetworkQualityEstimator::SocketWatcher : public SocketPerformanceWatcher {
 public:
  SocketWatcher(
      SocketPerformanceWatcherFactory::Protocol protocol,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      const base::WeakPtr<NetworkQualityEstimator>& network_quality_estimator)
      : protocol_(protocol),
        task_runner_(std::move(task_runner)),
        network_quality_estimator_(network_quality_estimator) {}

  ~SocketWatcher() override {}

  // SocketPerformanceWatcher implementation:
  bool ShouldNotifyUpdatedRTT() const override {
    DCHECK(thread_checker_.CalledOnValidThread());

    return true;
  }

  void OnUpdatedRTTAvailable(const base::TimeDelta& rtt) override {
    DCHECK(thread_checker_.CalledOnValidThread());

    task_runner_->PostTask(
        FROM_HERE, base::Bind(&NetworkQualityEstimator::OnUpdatedRTTAvailable,
                              network_quality_estimator_, protocol_, rtt));
  }

  void OnConnectionChanged() override {
    DCHECK(thread_checker_.CalledOnValidThread());
  }

 private:
  // Transport layer protocol used by the socket that |this| is watching.
  const SocketPerformanceWatcherFactory::Protocol protocol_;

  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  base::WeakPtr<NetworkQualityEstimator> network_quality_estimator_;

  base::ThreadChecker thread_checker_;

  DISALLOW_COPY_AND_ASSIGN(SocketWatcher);
};

// SocketWatcherFactory implements SocketPerformanceWatcherFactory, and is
// owned by NetworkQualityEstimator. SocketWatcherFactory is thread safe.
class NetworkQualityEstimator::SocketWatcherFactory
    : public SocketPerformanceWatcherFactory {
 public:
  SocketWatcherFactory(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      const base::WeakPtr<NetworkQualityEstimator>& network_quality_estimator)
      : task_runner_(std::move(task_runner)),
        network_quality_estimator_(network_quality_estimator) {}

  ~SocketWatcherFactory() override {}

  // SocketPerformanceWatcherFactory implementation:
  std::unique_ptr<SocketPerformanceWatcher> CreateSocketPerformanceWatcher(
      const Protocol protocol) override {
    return std::unique_ptr<SocketPerformanceWatcher>(
        new SocketWatcher(protocol, task_runner_, network_quality_estimator_));
  }

 private:
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  base::WeakPtr<NetworkQualityEstimator> network_quality_estimator_;

  DISALLOW_COPY_AND_ASSIGN(SocketWatcherFactory);
};

const int32_t NetworkQualityEstimator::kInvalidThroughput = 0;

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
    bool allow_local_host_requests_for_tests,
    bool allow_smaller_responses_for_tests)
    : allow_localhost_requests_(allow_local_host_requests_for_tests),
      allow_small_responses_(allow_smaller_responses_for_tests),
      weight_multiplier_per_second_(
          GetWeightMultiplierPerSecond(variation_params)),
      last_connection_change_(base::TimeTicks::Now()),
      current_network_id_(
          NetworkID(NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN,
                    std::string())),
      downstream_throughput_kbps_observations_(weight_multiplier_per_second_),
      rtt_observations_(weight_multiplier_per_second_),
      external_estimate_provider_(std::move(external_estimates_provider)),
      weak_ptr_factory_(this) {
  static_assert(kMinRequestDurationMicroseconds > 0,
                "Minimum request duration must be > 0");
  static_assert(kDefaultHalfLifeSeconds > 0,
                "Default half life duration must be > 0");
  static_assert(kMaximumNetworkQualityCacheSize > 0,
                "Size of the network quality cache must be > 0");
  // This limit should not be increased unless the logic for removing the
  // oldest cache entry is rewritten to use a doubly-linked-list LRU queue.
  static_assert(kMaximumNetworkQualityCacheSize <= 10,
                "Size of the network quality cache must <= 10");

  ObtainOperatingParams(variation_params);
  ObtainEffectiveConnectionTypeModelParams(variation_params);
  NetworkChangeNotifier::AddConnectionTypeObserver(this);
  if (external_estimate_provider_) {
    RecordExternalEstimateProviderMetrics(
        EXTERNAL_ESTIMATE_PROVIDER_STATUS_AVAILABLE);
    external_estimate_provider_->SetUpdatedEstimateDelegate(this);
    QueryExternalEstimateProvider();
  } else {
    RecordExternalEstimateProviderMetrics(
        EXTERNAL_ESTIMATE_PROVIDER_STATUS_NOT_AVAILABLE);
  }
  current_network_id_ = GetCurrentNetworkID();
  AddDefaultEstimates();

  watcher_factory_.reset(new SocketWatcherFactory(
      base::ThreadTaskRunnerHandle::Get(), weak_ptr_factory_.GetWeakPtr()));
}

// static
const base::TimeDelta NetworkQualityEstimator::InvalidRTT() {
  return base::TimeDelta::Max();
}

void NetworkQualityEstimator::ObtainOperatingParams(
    const std::map<std::string, std::string>& variation_params) {
  DCHECK(thread_checker_.CalledOnValidThread());

  for (size_t i = 0; i <= NetworkChangeNotifier::CONNECTION_LAST; ++i) {
    NetworkChangeNotifier::ConnectionType type =
        static_cast<NetworkChangeNotifier::ConnectionType>(i);
    DCHECK_EQ(InvalidRTT(), default_observations_[i].rtt());
    DCHECK_EQ(kInvalidThroughput,
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
      default_observations_[i] =
          NetworkQuality(base::TimeDelta::FromMilliseconds(variations_value),
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
      default_observations_[i] =
          NetworkQuality(default_observations_[i].rtt(), variations_value);
    }
  }
}

void NetworkQualityEstimator::ObtainEffectiveConnectionTypeModelParams(
    const std::map<std::string, std::string>& variation_params) {
  DCHECK(thread_checker_.CalledOnValidThread());

  for (size_t i = 0; i < EFFECTIVE_CONNECTION_TYPE_LAST; ++i) {
    EffectiveConnectionType effective_connection_type =
        static_cast<EffectiveConnectionType>(i);
    DCHECK_EQ(InvalidRTT(), connection_thresholds_[i].rtt());
    DCHECK_EQ(kInvalidThroughput,
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
      connection_thresholds_[i] = NetworkQuality(
          rtt, connection_thresholds_[i].downstream_throughput_kbps());

      // Verify that the RTT values are in decreasing order as the network
      // quality improves.
      DCHECK(i == 0 || connection_thresholds_[i - 1].rtt() == InvalidRTT() ||
             rtt <= connection_thresholds_[i - 1].rtt());
    }

    variations_value = kMinimumThroughputVariationParameterKbps - 1;
    if (GetValueForVariationParam(variation_params,
                                  connection_type_name + kThresholdKbpsSuffix,
                                  &variations_value) &&
        variations_value >= kMinimumThroughputVariationParameterKbps) {
      int32_t throughput_kbps = variations_value;
      connection_thresholds_[i] =
          NetworkQuality(connection_thresholds_[i].rtt(), throughput_kbps);

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
  if (default_observations_[current_network_id_.type].rtt() != InvalidRTT()) {
    RttObservation rtt_observation(
        default_observations_[current_network_id_.type].rtt(),
        base::TimeTicks::Now(), DEFAULT_FROM_PLATFORM);
    rtt_observations_.AddObservation(rtt_observation);
    NotifyObserversOfRTT(rtt_observation);
  }
  if (default_observations_[current_network_id_.type]
          .downstream_throughput_kbps() != kInvalidThroughput) {
    ThroughputObservation throughput_observation(
        default_observations_[current_network_id_.type]
            .downstream_throughput_kbps(),
        base::TimeTicks::Now(), DEFAULT_FROM_PLATFORM);
    downstream_throughput_kbps_observations_.AddObservation(
        throughput_observation);
    NotifyObserversOfThroughput(throughput_observation);
  }
}

NetworkQualityEstimator::~NetworkQualityEstimator() {
  DCHECK(thread_checker_.CalledOnValidThread());
  NetworkChangeNotifier::RemoveConnectionTypeObserver(this);
}

void NetworkQualityEstimator::NotifyHeadersReceived(const URLRequest& request) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("net"),
               "NetworkQualityEstimator::NotifyHeadersReceived");
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!RequestProvidesUsefulObservations(request))
    return;

  // Update |estimated_median_network_quality_| if this is a main frame request.
  if (request.load_flags() & LOAD_MAIN_FRAME) {
    estimated_median_network_quality_ = NetworkQuality(
        GetURLRequestRTTEstimateInternal(base::TimeTicks(), 50),
        GetDownlinkThroughputKbpsEstimateInternal(base::TimeTicks(), 50));
  }

  base::TimeTicks now = base::TimeTicks::Now();
  LoadTimingInfo load_timing_info;
  request.GetLoadTimingInfo(&load_timing_info);

  // If the load timing info is unavailable, it probably means that the request
  // did not go over the network.
  if (load_timing_info.send_start.is_null() ||
      load_timing_info.receive_headers_end.is_null()) {
    return;
  }

  // Time when the resource was requested.
  base::TimeTicks request_start_time = load_timing_info.send_start;

  // Time when the headers were received.
  base::TimeTicks headers_received_time = load_timing_info.receive_headers_end;

  // Duration between when the resource was requested and when response
  // headers were received.
  base::TimeDelta observed_rtt = headers_received_time - request_start_time;
  DCHECK_GE(observed_rtt, base::TimeDelta());
  if (observed_rtt < peak_network_quality_.rtt()) {
    peak_network_quality_ = NetworkQuality(
        observed_rtt, peak_network_quality_.downstream_throughput_kbps());
  }

  RttObservation rtt_observation(observed_rtt, now, URL_REQUEST);
  rtt_observations_.AddObservation(rtt_observation);
  NotifyObserversOfRTT(rtt_observation);

  // Compare the RTT observation with the estimated value and record it.
  if (estimated_median_network_quality_.rtt() != InvalidRTT()) {
    RecordRTTUMA(estimated_median_network_quality_.rtt().InMilliseconds(),
                 observed_rtt.InMilliseconds());
  }
}

void NetworkQualityEstimator::NotifyRequestCompleted(
    const URLRequest& request) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("net"),
               "NetworkQualityEstimator::NotifyRequestCompleted");
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!RequestProvidesUsefulObservations(request))
    return;

  base::TimeTicks now = base::TimeTicks::Now();
  LoadTimingInfo load_timing_info;
  request.GetLoadTimingInfo(&load_timing_info);

  // If the load timing info is unavailable, it probably means that the request
  // did not go over the network.
  if (load_timing_info.send_start.is_null() ||
      load_timing_info.receive_headers_end.is_null()) {
    return;
  }

  // Time since the resource was requested.
  // TODO(tbansal): Change the start time to receive_headers_end, once we use
  // NetworkActivityMonitor.
  base::TimeDelta request_start_to_completed =
      now - load_timing_info.send_start;
  DCHECK_GE(request_start_to_completed, base::TimeDelta());

  // Ignore tiny transfers which will not produce accurate rates.
  // Ignore short duration transfers.
  // Skip the checks if |allow_small_responses_| is true.
  if (!allow_small_responses_ &&
      (request.GetTotalReceivedBytes() < kMinTransferSizeInBytes ||
       request_start_to_completed < base::TimeDelta::FromMicroseconds(
                                        kMinRequestDurationMicroseconds))) {
    return;
  }

  double downstream_kbps = request.GetTotalReceivedBytes() * 8.0 / 1000.0 /
                           request_start_to_completed.InSecondsF();
  DCHECK_GE(downstream_kbps, 0.0);

  // Check overflow errors. This may happen if the downstream_kbps is more than
  // 2 * 10^9 (= 2000 Gbps).
  if (downstream_kbps >= std::numeric_limits<int32_t>::max())
    downstream_kbps = std::numeric_limits<int32_t>::max();

  int32_t downstream_kbps_as_integer = static_cast<int32_t>(downstream_kbps);

  // Round up |downstream_kbps_as_integer|. If the |downstream_kbps_as_integer|
  // is less than 1, it is set to 1 to differentiate from case when there is no
  // connection.
  if (downstream_kbps - downstream_kbps_as_integer > 0)
    downstream_kbps_as_integer++;

  DCHECK_GT(downstream_kbps_as_integer, 0.0);
  if (downstream_kbps_as_integer >
      peak_network_quality_.downstream_throughput_kbps())
    peak_network_quality_ =
        NetworkQuality(peak_network_quality_.rtt(), downstream_kbps_as_integer);

  ThroughputObservation throughput_observation(downstream_kbps_as_integer, now,
                                               URL_REQUEST);
  downstream_throughput_kbps_observations_.AddObservation(
      throughput_observation);
  NotifyObserversOfThroughput(throughput_observation);
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

void NetworkQualityEstimator::RecordRTTUMA(int32_t estimated_value_msec,
                                           int32_t actual_value_msec) const {
  DCHECK(thread_checker_.CalledOnValidThread());

  // Record the difference between the actual and the estimated value.
  if (estimated_value_msec >= actual_value_msec) {
    base::HistogramBase* difference_rtt =
        GetHistogram("DifferenceRTTEstimatedAndActual.",
                     current_network_id_.type, 10 * 1000);  // 10 seconds
    difference_rtt->Add(estimated_value_msec - actual_value_msec);
  } else {
    base::HistogramBase* difference_rtt =
        GetHistogram("DifferenceRTTActualAndEstimated.",
                     current_network_id_.type, 10 * 1000);  // 10 seconds
    difference_rtt->Add(actual_value_msec - estimated_value_msec);
  }

  // Record all the RTT observations.
  base::HistogramBase* rtt_observations =
      GetHistogram("RTTObservations.", current_network_id_.type,
                   10 * 1000);  // 10 seconds upper bound
  rtt_observations->Add(actual_value_msec);

  if (actual_value_msec == 0)
    return;

  int32_t ratio = (estimated_value_msec * 100) / actual_value_msec;

  // Record the accuracy of estimation by recording the ratio of estimated
  // value to the actual value.
  base::HistogramBase* ratio_median_rtt = GetHistogram(
      "RatioEstimatedToActualRTT.", current_network_id_.type, 1000);
  ratio_median_rtt->Add(ratio);
}

bool NetworkQualityEstimator::RequestProvidesUsefulObservations(
    const URLRequest& request) const {
  return request.url().is_valid() &&
         (allow_localhost_requests_ || !IsLocalhost(request.url().host())) &&
         request.url().SchemeIsHTTPOrHTTPS() &&
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
  if (peak_network_quality_.rtt() != InvalidRTT()) {
    switch (current_network_id_.type) {
      case NetworkChangeNotifier::CONNECTION_UNKNOWN:
        UMA_HISTOGRAM_TIMES("NQE.FastestRTT.Unknown",
                            peak_network_quality_.rtt());
        break;
      case NetworkChangeNotifier::CONNECTION_ETHERNET:
        UMA_HISTOGRAM_TIMES("NQE.FastestRTT.Ethernet",
                            peak_network_quality_.rtt());
        break;
      case NetworkChangeNotifier::CONNECTION_WIFI:
        UMA_HISTOGRAM_TIMES("NQE.FastestRTT.Wifi", peak_network_quality_.rtt());
        break;
      case NetworkChangeNotifier::CONNECTION_2G:
        UMA_HISTOGRAM_TIMES("NQE.FastestRTT.2G", peak_network_quality_.rtt());
        break;
      case NetworkChangeNotifier::CONNECTION_3G:
        UMA_HISTOGRAM_TIMES("NQE.FastestRTT.3G", peak_network_quality_.rtt());
        break;
      case NetworkChangeNotifier::CONNECTION_4G:
        UMA_HISTOGRAM_TIMES("NQE.FastestRTT.4G", peak_network_quality_.rtt());
        break;
      case NetworkChangeNotifier::CONNECTION_NONE:
        UMA_HISTOGRAM_TIMES("NQE.FastestRTT.None", peak_network_quality_.rtt());
        break;
      case NetworkChangeNotifier::CONNECTION_BLUETOOTH:
        UMA_HISTOGRAM_TIMES("NQE.FastestRTT.Bluetooth",
                            peak_network_quality_.rtt());
        break;
      default:
        NOTREACHED() << "Unexpected connection type = "
                     << current_network_id_.type;
        break;
    }
  }

  if (peak_network_quality_.downstream_throughput_kbps() !=
      kInvalidThroughput) {
    switch (current_network_id_.type) {
      case NetworkChangeNotifier::CONNECTION_UNKNOWN:
        UMA_HISTOGRAM_COUNTS(
            "NQE.PeakKbps.Unknown",
            peak_network_quality_.downstream_throughput_kbps());
        break;
      case NetworkChangeNotifier::CONNECTION_ETHERNET:
        UMA_HISTOGRAM_COUNTS(
            "NQE.PeakKbps.Ethernet",
            peak_network_quality_.downstream_throughput_kbps());
        break;
      case NetworkChangeNotifier::CONNECTION_WIFI:
        UMA_HISTOGRAM_COUNTS(
            "NQE.PeakKbps.Wifi",
            peak_network_quality_.downstream_throughput_kbps());
        break;
      case NetworkChangeNotifier::CONNECTION_2G:
        UMA_HISTOGRAM_COUNTS(
            "NQE.PeakKbps.2G",
            peak_network_quality_.downstream_throughput_kbps());
        break;
      case NetworkChangeNotifier::CONNECTION_3G:
        UMA_HISTOGRAM_COUNTS(
            "NQE.PeakKbps.3G",
            peak_network_quality_.downstream_throughput_kbps());
        break;
      case NetworkChangeNotifier::CONNECTION_4G:
        UMA_HISTOGRAM_COUNTS(
            "NQE.PeakKbps.4G",
            peak_network_quality_.downstream_throughput_kbps());
        break;
      case NetworkChangeNotifier::CONNECTION_NONE:
        UMA_HISTOGRAM_COUNTS(
            "NQE.PeakKbps.None",
            peak_network_quality_.downstream_throughput_kbps());
        break;
      case NetworkChangeNotifier::CONNECTION_BLUETOOTH:
        UMA_HISTOGRAM_COUNTS(
            "NQE.PeakKbps.Bluetooth",
            peak_network_quality_.downstream_throughput_kbps());
        break;
      default:
        NOTREACHED() << "Unexpected connection type = "
                     << current_network_id_.type;
        break;
    }
  }

  base::TimeDelta rtt = GetURLRequestRTTEstimateInternal(base::TimeTicks(), 50);
  if (rtt != InvalidRTT()) {
    // Add the 50th percentile value.
    base::HistogramBase* rtt_percentile =
        GetHistogram("RTT.Percentile50.", current_network_id_.type,
                     10 * 1000);  // 10 seconds
    rtt_percentile->Add(rtt.InMilliseconds());

    // Add the remaining percentile values.
    static const int kPercentiles[] = {0, 10, 90, 100};
    for (size_t i = 0; i < arraysize(kPercentiles); ++i) {
      rtt =
          GetURLRequestRTTEstimateInternal(base::TimeTicks(), kPercentiles[i]);

      rtt_percentile = GetHistogram(
          "RTT.Percentile" + base::IntToString(kPercentiles[i]) + ".",
          current_network_id_.type, 10 * 1000);  // 10 seconds
      rtt_percentile->Add(rtt.InMilliseconds());
    }
  }

  // Write the estimates of the previous network to the cache.
  CacheNetworkQualityEstimate();

  // Clear the local state.
  last_connection_change_ = base::TimeTicks::Now();
  peak_network_quality_ = NetworkQuality();
  downstream_throughput_kbps_observations_.Clear();
  rtt_observations_.Clear();
  current_network_id_ = GetCurrentNetworkID();

  QueryExternalEstimateProvider();

  // Read any cached estimates for the new network. If cached estimates are
  // unavailable, add the default estimates.
  if (!ReadCachedNetworkQualityEstimate())
    AddDefaultEstimates();
  estimated_median_network_quality_ = NetworkQuality();
}

NetworkQualityEstimator::EffectiveConnectionType
NetworkQualityEstimator::GetEffectiveConnectionType() const {
  DCHECK(thread_checker_.CalledOnValidThread());

  base::TimeDelta url_request_rtt = InvalidRTT();
  if (!GetURLRequestRTTEstimate(&url_request_rtt))
    url_request_rtt = InvalidRTT();

  int32_t kbps = kInvalidThroughput;
  if (!GetDownlinkThroughputKbpsEstimate(&kbps))
    kbps = kInvalidThroughput;

  if (url_request_rtt == InvalidRTT() && kbps == kInvalidThroughput) {
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
    bool estimated_rtt_is_higher_than_threshold =
        url_request_rtt != InvalidRTT() &&
        connection_thresholds_[i].rtt() != InvalidRTT() &&
        url_request_rtt >= connection_thresholds_[i].rtt();
    bool estimated_throughput_is_lower_than_threshold =
        kbps != kInvalidThroughput &&
        connection_thresholds_[i].downstream_throughput_kbps() !=
            kInvalidThroughput &&
        kbps <= connection_thresholds_[i].downstream_throughput_kbps();
    // Return |type| as the effective connection type if the current network's
    // RTT is worse than the threshold RTT for |type|, or if the current
    // network's throughput is lower than the threshold throughput for |type|.
    if (estimated_rtt_is_higher_than_threshold ||
        estimated_throughput_is_lower_than_threshold) {
      return type;
    }
  }
  // Return the fastest connection type.
  return static_cast<EffectiveConnectionType>(EFFECTIVE_CONNECTION_TYPE_LAST -
                                              1);
}

bool NetworkQualityEstimator::GetURLRequestRTTEstimate(
    base::TimeDelta* rtt) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(rtt);
  if (rtt_observations_.Size() == 0) {
    *rtt = InvalidRTT();
    return false;
  }
  *rtt = GetURLRequestRTTEstimateInternal(base::TimeTicks(), 50);
  return (*rtt != InvalidRTT());
}

bool NetworkQualityEstimator::GetDownlinkThroughputKbpsEstimate(
    int32_t* kbps) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(kbps);
  if (downstream_throughput_kbps_observations_.Size() == 0) {
    *kbps = kInvalidThroughput;
    return false;
  }
  *kbps = GetDownlinkThroughputKbpsEstimateInternal(base::TimeTicks(), 50);
  return (*kbps != kInvalidThroughput);
}

bool NetworkQualityEstimator::GetRecentURLRequestRTTMedian(
    const base::TimeTicks& begin_timestamp,
    base::TimeDelta* rtt) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(rtt);
  *rtt = GetURLRequestRTTEstimateInternal(begin_timestamp, 50);
  return (*rtt != InvalidRTT());
}

bool NetworkQualityEstimator::GetRecentMedianDownlinkThroughputKbps(
    const base::TimeTicks& begin_timestamp,
    int32_t* kbps) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(kbps);
  *kbps = GetDownlinkThroughputKbpsEstimateInternal(begin_timestamp, 50);
  return (*kbps != kInvalidThroughput);
}

template <typename ValueType>
NetworkQualityEstimator::ObservationBuffer<ValueType>::ObservationBuffer(
    double weight_multiplier_per_second)
    : weight_multiplier_per_second_(weight_multiplier_per_second) {
  static_assert(kMaximumObservationsBufferSize > 0U,
                "Minimum size of observation buffer must be > 0");
  DCHECK_GE(weight_multiplier_per_second_, 0.0);
  DCHECK_LE(weight_multiplier_per_second_, 1.0);
}

template <typename ValueType>
NetworkQualityEstimator::ObservationBuffer<ValueType>::~ObservationBuffer() {}

base::TimeDelta NetworkQualityEstimator::GetURLRequestRTTEstimateInternal(
    const base::TimeTicks& begin_timestamp,
    int percentile) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_GE(percentile, 0);
  DCHECK_LE(percentile, 100);
  if (rtt_observations_.Size() == 0)
    return InvalidRTT();

  // RTT observations are sorted by duration from shortest to longest, thus
  // a higher percentile RTT will have a longer RTT than a lower percentile.
  base::TimeDelta rtt = InvalidRTT();
  std::vector<ObservationSource> disallowed_observation_sources;
  disallowed_observation_sources.push_back(TCP);
  disallowed_observation_sources.push_back(QUIC);
  rtt_observations_.GetPercentile(begin_timestamp, &rtt, percentile,
                                  disallowed_observation_sources);
  return rtt;
}

int32_t NetworkQualityEstimator::GetDownlinkThroughputKbpsEstimateInternal(
    const base::TimeTicks& begin_timestamp,
    int percentile) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_GE(percentile, 0);
  DCHECK_LE(percentile, 100);
  if (downstream_throughput_kbps_observations_.Size() == 0)
    return kInvalidThroughput;

  // Throughput observations are sorted by kbps from slowest to fastest,
  // thus a higher percentile throughput will be faster than a lower one.
  int32_t kbps = kInvalidThroughput;
  downstream_throughput_kbps_observations_.GetPercentile(
      begin_timestamp, &kbps, 100 - percentile,
      std::vector<ObservationSource>());
  return kbps;
}

template <typename ValueType>
void NetworkQualityEstimator::ObservationBuffer<ValueType>::
    ComputeWeightedObservations(
        const base::TimeTicks& begin_timestamp,
        std::vector<WeightedObservation<ValueType>>& weighted_observations,
        double* total_weight,
        const std::vector<ObservationSource>& disallowed_observation_sources)
        const {
  weighted_observations.clear();
  double total_weight_observations = 0.0;
  base::TimeTicks now = base::TimeTicks::Now();

  for (const auto& observation : observations_) {
    if (observation.timestamp < begin_timestamp)
      continue;
    bool disallowed = false;
    for (const auto& disallowed_source : disallowed_observation_sources) {
      if (disallowed_source == observation.source)
        disallowed = true;
    }
    if (disallowed)
      continue;
    base::TimeDelta time_since_sample_taken = now - observation.timestamp;
    double weight =
        pow(weight_multiplier_per_second_, time_since_sample_taken.InSeconds());
    weight = std::max(DBL_MIN, std::min(1.0, weight));

    weighted_observations.push_back(
        WeightedObservation<ValueType>(observation.value, weight));
    total_weight_observations += weight;
  }

  // Sort the samples by value in ascending order.
  std::sort(weighted_observations.begin(), weighted_observations.end());
  *total_weight = total_weight_observations;
}

template <typename ValueType>
bool NetworkQualityEstimator::ObservationBuffer<ValueType>::GetPercentile(
    const base::TimeTicks& begin_timestamp,
    ValueType* result,
    int percentile,
    const std::vector<ObservationSource>& disallowed_observation_sources)
    const {
  DCHECK(result);
  // Stores WeightedObservation in increasing order of value.
  std::vector<WeightedObservation<ValueType>> weighted_observations;

  // Total weight of all observations in |weighted_observations|.
  double total_weight = 0.0;

  ComputeWeightedObservations(begin_timestamp, weighted_observations,
                              &total_weight, disallowed_observation_sources);
  if (weighted_observations.empty())
    return false;

  DCHECK(!weighted_observations.empty());
  DCHECK_GT(total_weight, 0.0);

  // weighted_observations may have a smaller size than observations_ since the
  // former contains only the observations later than begin_timestamp.
  DCHECK_GE(observations_.size(), weighted_observations.size());

  double desired_weight = percentile / 100.0 * total_weight;

  double cumulative_weight_seen_so_far = 0.0;
  for (const auto& weighted_observation : weighted_observations) {
    cumulative_weight_seen_so_far += weighted_observation.weight;

    if (cumulative_weight_seen_so_far >= desired_weight) {
      *result = weighted_observation.value;
      return true;
    }
  }

  // Computation may reach here due to floating point errors. This may happen
  // if |percentile| was 100 (or close to 100), and |desired_weight| was
  // slightly larger than |total_weight| (due to floating point errors).
  // In this case, we return the highest |value| among all observations.
  // This is same as value of the last observation in the sorted vector.
  *result = weighted_observations.at(weighted_observations.size() - 1).value;
  return true;
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

  NetworkQuality network_quality(it->second.network_quality());

  DCHECK_NE(InvalidRTT(), network_quality.rtt());
  DCHECK_NE(kInvalidThroughput, network_quality.downstream_throughput_kbps());

  ThroughputObservation througphput_observation(
      network_quality.downstream_throughput_kbps(), base::TimeTicks::Now(),
      CACHED_ESTIMATE);
  downstream_throughput_kbps_observations_.AddObservation(
      througphput_observation);
  NotifyObserversOfThroughput(througphput_observation);

  RttObservation rtt_observation(network_quality.rtt(), base::TimeTicks::Now(),
                                 CACHED_ESTIMATE);
  rtt_observations_.AddObservation(rtt_observation);
  NotifyObserversOfRTT(rtt_observation);

  return true;
}

void NetworkQualityEstimator::OnUpdatedEstimateAvailable() {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(external_estimate_provider_);

  RecordExternalEstimateProviderMetrics(
      EXTERNAL_ESTIMATE_PROVIDER_STATUS_CALLBACK);
  QueryExternalEstimateProvider();
}

const char* NetworkQualityEstimator::GetNameForEffectiveConnectionType(
    EffectiveConnectionType type) const {
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

void NetworkQualityEstimator::QueryExternalEstimateProvider() {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!external_estimate_provider_)
    return;
  RecordExternalEstimateProviderMetrics(
      EXTERNAL_ESTIMATE_PROVIDER_STATUS_QUERIED);

  base::TimeDelta time_since_last_update;

  // Request a new estimate if estimate is not available, or if the available
  // estimate is not fresh.
  if (!external_estimate_provider_->GetTimeSinceLastUpdate(
          &time_since_last_update) ||
      time_since_last_update >
          base::TimeDelta::FromMilliseconds(
              kExternalEstimateProviderFreshnessDurationMsec)) {
    // Request the external estimate provider for updated estimates. When the
    // updates estimates are available, OnUpdatedEstimateAvailable() will be
    // called.
    external_estimate_provider_->Update();
    return;
  }

  RecordExternalEstimateProviderMetrics(
      EXTERNAL_ESTIMATE_PROVIDER_STATUS_QUERY_SUCCESSFUL);
  base::TimeDelta rtt;
  if (external_estimate_provider_->GetRTT(&rtt)) {
    rtt_observations_.AddObservation(
        RttObservation(rtt, base::TimeTicks::Now(), EXTERNAL_ESTIMATE));
  }

  int32_t downstream_throughput_kbps;
  if (external_estimate_provider_->GetDownstreamThroughputKbps(
          &downstream_throughput_kbps)) {
    downstream_throughput_kbps_observations_.AddObservation(
        ThroughputObservation(downstream_throughput_kbps,
                              base::TimeTicks::Now(), EXTERNAL_ESTIMATE));
  }
}

void NetworkQualityEstimator::CacheNetworkQualityEstimate() {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_LE(cached_network_qualities_.size(),
            static_cast<size_t>(kMaximumNetworkQualityCacheSize));

  // If the network name is unavailable, caching should not be performed.
  if (current_network_id_.id.empty())
    return;

  NetworkQuality network_quality = NetworkQuality(
      GetURLRequestRTTEstimateInternal(base::TimeTicks(), 50),
      GetDownlinkThroughputKbpsEstimateInternal(base::TimeTicks(), 50));
  if (network_quality.rtt() == InvalidRTT() ||
      network_quality.downstream_throughput_kbps() == kInvalidThroughput) {
    return;
  }

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

  cached_network_qualities_.insert(std::make_pair(
      current_network_id_, CachedNetworkQuality(network_quality)));
  DCHECK_LE(cached_network_qualities_.size(),
            static_cast<size_t>(kMaximumNetworkQualityCacheSize));
}

void NetworkQualityEstimator::OnUpdatedRTTAvailable(
    SocketPerformanceWatcherFactory::Protocol protocol,
    const base::TimeDelta& rtt) {
  DCHECK(thread_checker_.CalledOnValidThread());

  switch (protocol) {
    case SocketPerformanceWatcherFactory::PROTOCOL_TCP:
      NotifyObserversOfRTT(RttObservation(rtt, base::TimeTicks::Now(), TCP));
      return;
    case SocketPerformanceWatcherFactory::PROTOCOL_QUIC:
      NotifyObserversOfRTT(RttObservation(rtt, base::TimeTicks::Now(), QUIC));
      return;
    default:
      NOTREACHED();
  }
}

void NetworkQualityEstimator::NotifyObserversOfRTT(
    const RttObservation& observation) {
  FOR_EACH_OBSERVER(
      RTTObserver, rtt_observer_list_,
      OnRTTObservation(observation.value.InMilliseconds(),
                       observation.timestamp, observation.source));
}

void NetworkQualityEstimator::NotifyObserversOfThroughput(
    const ThroughputObservation& observation) {
  FOR_EACH_OBSERVER(
      ThroughputObserver, throughput_observer_list_,
      OnThroughputObservation(observation.value, observation.timestamp,
                              observation.source));
}

NetworkQualityEstimator::CachedNetworkQuality::CachedNetworkQuality(
    const NetworkQuality& network_quality)
    : last_update_time_(base::TimeTicks::Now()),
      network_quality_(network_quality) {
}

NetworkQualityEstimator::CachedNetworkQuality::CachedNetworkQuality(
    const CachedNetworkQuality& other)
    : last_update_time_(other.last_update_time_),
      network_quality_(other.network_quality_) {
}

NetworkQualityEstimator::CachedNetworkQuality::~CachedNetworkQuality() {
}

bool NetworkQualityEstimator::CachedNetworkQuality::OlderThan(
    const CachedNetworkQuality& cached_network_quality) const {
  return last_update_time_ < cached_network_quality.last_update_time_;
}

NetworkQualityEstimator::NetworkQuality::NetworkQuality()
    : NetworkQuality(NetworkQualityEstimator::InvalidRTT(),
                     NetworkQualityEstimator::kInvalidThroughput) {}

NetworkQualityEstimator::NetworkQuality::NetworkQuality(
    const base::TimeDelta& rtt,
    int32_t downstream_throughput_kbps)
    : rtt_(rtt), downstream_throughput_kbps_(downstream_throughput_kbps) {
  DCHECK_GE(rtt_, base::TimeDelta());
  DCHECK_GE(downstream_throughput_kbps_, 0);
}

NetworkQualityEstimator::NetworkQuality::NetworkQuality(
    const NetworkQuality& other)
    : NetworkQuality(other.rtt_, other.downstream_throughput_kbps_) {}

NetworkQualityEstimator::NetworkQuality::~NetworkQuality() {}

NetworkQualityEstimator::NetworkQuality&
    NetworkQualityEstimator::NetworkQuality::
    operator=(const NetworkQuality& other) {
  rtt_ = other.rtt_;
  downstream_throughput_kbps_ = other.downstream_throughput_kbps_;
  return *this;
}

}  // namespace net

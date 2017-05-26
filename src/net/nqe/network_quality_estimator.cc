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
#include "base/metrics/histogram_macros.h"
#include "base/metrics/sparse_histogram.h"
#include "base/rand_util.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/default_tick_clock.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "net/base/load_flags.h"
#include "net/base/load_timing_info.h"
#include "net/base/network_interfaces.h"
#include "net/base/trace_constants.h"
#include "net/base/url_util.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_status_code.h"
#include "net/nqe/socket_watcher_factory.h"
#include "net/nqe/throughput_analyzer.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_status.h"
#include "url/gurl.h"

#if defined(OS_ANDROID)
#include "net/android/cellular_signal_strength.h"
#include "net/android/network_library.h"
#endif  // OS_ANDROID

namespace net {

namespace {

// Returns the histogram that should be used to record the given statistic.
// |max_limit| is the maximum value that can be stored in the histogram.
base::HistogramBase* GetHistogram(const std::string& statistic_name,
                                  NetworkChangeNotifier::ConnectionType type,
                                  int32_t max_limit) {
  const base::LinearHistogram::Sample kLowerLimit = 1;
  DCHECK_GT(max_limit, kLowerLimit);
  const size_t kBucketCount = 50;

  return base::Histogram::FactoryGet(
      "NQE." + statistic_name +
          nqe::internal::NetworkQualityEstimatorParams::
              GetNameForConnectionType(type),
      kLowerLimit, max_limit, kBucketCount,
      base::HistogramBase::kUmaTargetedHistogramFlag);
}

NetworkQualityObservationSource ProtocolSourceToObservationSource(
    SocketPerformanceWatcherFactory::Protocol protocol) {
  switch (protocol) {
    case SocketPerformanceWatcherFactory::PROTOCOL_TCP:
      return NETWORK_QUALITY_OBSERVATION_SOURCE_TCP;
    case SocketPerformanceWatcherFactory::PROTOCOL_QUIC:
      return NETWORK_QUALITY_OBSERVATION_SOURCE_QUIC;
  }
  NOTREACHED();
  return NETWORK_QUALITY_OBSERVATION_SOURCE_TCP;
}

// Returns true if the scheme of the |request| is either HTTP or HTTPS.
bool RequestSchemeIsHTTPOrHTTPS(const URLRequest& request) {
  return request.url().is_valid() && request.url().SchemeIsHTTPOrHTTPS();
}

// Returns the suffix of the histogram that should be used for recording the
// accuracy when the observed RTT is |observed_rtt|. The width of the intervals
// are in exponentially increasing order.
const char* GetHistogramSuffixObservedRTT(const base::TimeDelta& observed_rtt) {
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
const char* GetHistogramSuffixObservedThroughput(
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

// The least significant kTrimBits of the metric will be discarded. If the
// trimmed metric value is greater than what can be fit in kBitsPerMetric bits,
// then the largest value that can be represented in kBitsPerMetric bits is
// returned.
const int32_t kTrimBits = 5;

// Maximum number of bits in which one metric should fit. Restricting the amount
// of space allocated to a single metric makes it possile to fit multiple
// metrics in a single histogram sample, and ensures that all those metrics
// are recorded together as a single tuple.
const int32_t kBitsPerMetric = 7;

static_assert(32 >= kBitsPerMetric * 4,
              "Four metrics would not fit in a 32-bit int");

// Trims the |metric| by removing the last kTrimBits, and then rounding down
// the |metric| such that the |metric| fits in kBitsPerMetric.
int32_t FitInKBitsPerMetricBits(int32_t metric) {
  // Remove the last kTrimBits. This will allow the metric to fit within
  // kBitsPerMetric while losing only the least significant bits.
  DCHECK_LE(0, metric);
  metric = metric >> kTrimBits;

  // kLargestValuePossible is the largest value that can be recorded using
  // kBitsPerMetric.
  static const int32_t kLargestValuePossible = (1 << kBitsPerMetric) - 1;
  if (metric > kLargestValuePossible) {
    // Fit |metric| in kBitsPerMetric by clamping it down.
    metric = kLargestValuePossible;
  }
  DCHECK_EQ(0, metric >> kBitsPerMetric) << metric;
  return metric;
}

void RecordRTTAccuracy(base::StringPiece prefix,
                       int32_t metric,
                       base::TimeDelta measuring_duration,
                       base::TimeDelta observed_rtt) {
  const std::string histogram_name =
      base::StringPrintf("%s.EstimatedObservedDiff.%s.%d.%s", prefix.data(),
                         metric >= 0 ? "Positive" : "Negative",
                         static_cast<int32_t>(measuring_duration.InSeconds()),
                         GetHistogramSuffixObservedRTT(observed_rtt));

  base::HistogramBase* histogram = base::Histogram::FactoryGet(
      histogram_name, 1, 10 * 1000 /* 10 seconds */, 50 /* Number of buckets */,
      base::HistogramBase::kUmaTargetedHistogramFlag);
  histogram->Add(std::abs(metric));
}

void RecordThroughputAccuracy(const char* prefix,
                              int32_t metric,
                              base::TimeDelta measuring_duration,
                              int32_t observed_throughput_kbps) {
  const std::string histogram_name = base::StringPrintf(
      "%s.EstimatedObservedDiff.%s.%d.%s", prefix,
      metric >= 0 ? "Positive" : "Negative",
      static_cast<int32_t>(measuring_duration.InSeconds()),
      GetHistogramSuffixObservedThroughput(observed_throughput_kbps));

  base::HistogramBase* histogram = base::Histogram::FactoryGet(
      histogram_name, 1, 1000 * 1000 /* 1 Gbps */, 50 /* Number of buckets */,
      base::HistogramBase::kUmaTargetedHistogramFlag);
  histogram->Add(std::abs(metric));
}

void RecordEffectiveConnectionTypeAccuracy(
    const char* prefix,
    int32_t metric,
    base::TimeDelta measuring_duration,
    EffectiveConnectionType observed_effective_connection_type) {
  const std::string histogram_name =
      base::StringPrintf("%s.EstimatedObservedDiff.%s.%d.%s", prefix,
                         metric >= 0 ? "Positive" : "Negative",
                         static_cast<int32_t>(measuring_duration.InSeconds()),
                         DeprecatedGetNameForEffectiveConnectionType(
                             observed_effective_connection_type));

  base::HistogramBase* histogram = base::Histogram::FactoryGet(
      histogram_name, 0, EFFECTIVE_CONNECTION_TYPE_LAST,
      EFFECTIVE_CONNECTION_TYPE_LAST /* Number of buckets */,
      base::HistogramBase::kUmaTargetedHistogramFlag);
  histogram->Add(std::abs(metric));
}

}  // namespace

NetworkQualityEstimator::NetworkQualityEstimator(
    std::unique_ptr<ExternalEstimateProvider> external_estimates_provider,
    const std::map<std::string, std::string>& variation_params,
    NetLog* net_log)
    : NetworkQualityEstimator(std::move(external_estimates_provider),
                              variation_params,
                              false,
                              false,
                              net_log) {}

NetworkQualityEstimator::NetworkQualityEstimator(
    std::unique_ptr<ExternalEstimateProvider> external_estimates_provider,
    const std::map<std::string, std::string>& variation_params,
    bool use_local_host_requests_for_tests,
    bool use_smaller_responses_for_tests,
    NetLog* net_log)
    : NetworkQualityEstimator(
          std::move(external_estimates_provider),
          variation_params,
          use_local_host_requests_for_tests,
          use_smaller_responses_for_tests,
          true,
          NetLogWithSource::Make(
              net_log,
              net::NetLogSourceType::NETWORK_QUALITY_ESTIMATOR)) {}

NetworkQualityEstimator::NetworkQualityEstimator(
    std::unique_ptr<ExternalEstimateProvider> external_estimates_provider,
    const std::map<std::string, std::string>& variation_params,
    bool use_local_host_requests_for_tests,
    bool use_smaller_responses_for_tests,
    bool add_default_platform_observations,
    const NetLogWithSource& net_log)
    : algorithm_name_to_enum_({{"HttpRTTAndDownstreamThroughput",
                                EffectiveConnectionTypeAlgorithm::
                                    HTTP_RTT_AND_DOWNSTREAM_THROUGHOUT},
                               {"TransportRTTOrDownstreamThroughput",
                                EffectiveConnectionTypeAlgorithm::
                                    TRANSPORT_RTT_OR_DOWNSTREAM_THROUGHOUT}}),
      params_(variation_params),
      use_localhost_requests_(use_local_host_requests_for_tests),
      use_small_responses_(use_smaller_responses_for_tests),
      disable_offline_check_(false),
      add_default_platform_observations_(add_default_platform_observations),
      effective_connection_type_algorithm_(
          algorithm_name_to_enum_.find(
              params_.GetEffectiveConnectionTypeAlgorithm()) ==
                  algorithm_name_to_enum_.end()
              ? kDefaultEffectiveConnectionTypeAlgorithm
              : algorithm_name_to_enum_
                    .find(params_.GetEffectiveConnectionTypeAlgorithm())
                    ->second),
      tick_clock_(new base::DefaultTickClock()),
      last_connection_change_(tick_clock_->NowTicks()),
      current_network_id_(nqe::internal::NetworkID(
          NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN,
          std::string())),
      downstream_throughput_kbps_observations_(
          params_.weight_multiplier_per_second(),
          params_.weight_multiplier_per_dbm()),
      rtt_observations_(params_.weight_multiplier_per_second(),
                        params_.weight_multiplier_per_dbm()),
      effective_connection_type_at_last_main_frame_(
          EFFECTIVE_CONNECTION_TYPE_UNKNOWN),
      external_estimate_provider_(std::move(external_estimates_provider)),
      effective_connection_type_recomputation_interval_(
          base::TimeDelta::FromSeconds(10)),
      rtt_observations_size_at_last_ect_computation_(0),
      throughput_observations_size_at_last_ect_computation_(0),
      effective_connection_type_(EFFECTIVE_CONNECTION_TYPE_UNKNOWN),
      signal_strength_dbm_(INT32_MIN),
      min_signal_strength_since_connection_change_(INT32_MAX),
      max_signal_strength_since_connection_change_(INT32_MIN),
      event_creator_(net_log),
      disallowed_observation_sources_for_http_(
          {NETWORK_QUALITY_OBSERVATION_SOURCE_TCP,
           NETWORK_QUALITY_OBSERVATION_SOURCE_QUIC,
           NETWORK_QUALITY_OBSERVATION_SOURCE_TRANSPORT_CACHED_ESTIMATE,
           NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_TRANSPORT_FROM_PLATFORM}),
      disallowed_observation_sources_for_transport_(
          {NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP,
           NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_EXTERNAL_ESTIMATE,
           NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_CACHED_ESTIMATE,
           NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_HTTP_FROM_PLATFORM}),
      weak_ptr_factory_(this) {
  // None of the algorithms can have an empty name.
  DCHECK(algorithm_name_to_enum_.end() ==
         algorithm_name_to_enum_.find(std::string()));

  DCHECK_EQ(algorithm_name_to_enum_.size(),
            static_cast<size_t>(EffectiveConnectionTypeAlgorithm::
                                    EFFECTIVE_CONNECTION_TYPE_ALGORITHM_LAST));
  DCHECK_NE(EffectiveConnectionTypeAlgorithm::
                EFFECTIVE_CONNECTION_TYPE_ALGORITHM_LAST,
            effective_connection_type_algorithm_);

  network_quality_store_.reset(new nqe::internal::NetworkQualityStore());
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
      &params_, base::ThreadTaskRunnerHandle::Get(),
      base::Bind(&NetworkQualityEstimator::OnNewThroughputObservationAvailable,
                 base::Unretained(this)),
      use_localhost_requests_, use_smaller_responses_for_tests));

  watcher_factory_.reset(new nqe::internal::SocketWatcherFactory(
      base::ThreadTaskRunnerHandle::Get(),
      params_.min_socket_watcher_notification_interval(),
      base::Bind(&NetworkQualityEstimator::OnUpdatedRTTAvailable,
                 base::Unretained(this)),
      tick_clock_.get()));

  // Record accuracy after a 15 second interval. The values used here must
  // remain in sync with the suffixes specified in
  // tools/metrics/histograms/histograms.xml.
  accuracy_recording_intervals_.push_back(base::TimeDelta::FromSeconds(15));

  for (int i = 0; i < STATISTIC_LAST; ++i)
    http_rtt_at_last_main_frame_[i] = nqe::internal::InvalidRTT();
}

void NetworkQualityEstimator::AddDefaultEstimates() {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!add_default_platform_observations_)
    return;

  if (params_.DefaultObservation(current_network_id_.type).http_rtt() !=
      nqe::internal::InvalidRTT()) {
    RttObservation rtt_observation(
        params_.DefaultObservation(current_network_id_.type).http_rtt(),
        tick_clock_->NowTicks(), INT32_MIN,
        NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_HTTP_FROM_PLATFORM);
    rtt_observations_.AddObservation(rtt_observation);
    NotifyObserversOfRTT(rtt_observation);
  }

  if (params_.DefaultObservation(current_network_id_.type).transport_rtt() !=
      nqe::internal::InvalidRTT()) {
    RttObservation rtt_observation(
        params_.DefaultObservation(current_network_id_.type).transport_rtt(),
        tick_clock_->NowTicks(), INT32_MIN,
        NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_TRANSPORT_FROM_PLATFORM);
    rtt_observations_.AddObservation(rtt_observation);
    NotifyObserversOfRTT(rtt_observation);
  }

  if (params_.DefaultObservation(current_network_id_.type)
          .downstream_throughput_kbps() != nqe::internal::kInvalidThroughput) {
    ThroughputObservation throughput_observation(
        params_.DefaultObservation(current_network_id_.type)
            .downstream_throughput_kbps(),
        tick_clock_->NowTicks(), INT32_MIN,
        NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_HTTP_FROM_PLATFORM);
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

  // Update |estimated_quality_at_last_main_frame_| if this is a main frame
  // request.
  // TODO(tbansal): Refactor this to a separate method.
  if (request.load_flags() & LOAD_MAIN_FRAME_DEPRECATED) {
    base::TimeTicks now = tick_clock_->NowTicks();
    last_main_frame_request_ = now;

    MaybeComputeEffectiveConnectionType();
    effective_connection_type_at_last_main_frame_ = effective_connection_type_;
    estimated_quality_at_last_main_frame_ = network_quality_;

    // Record the HTTP at the last main frame for experimental statistics.
    for (int i = 0; i < STATISTIC_LAST; ++i) {
      http_rtt_at_last_main_frame_[i] = GetRTTEstimateInternal(
          disallowed_observation_sources_for_http_, base::TimeTicks(),
          static_cast<Statistic>(i), 50);
    }

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
  throughput_analyzer_->NotifyStartTransaction(request);
}

void NetworkQualityEstimator::NotifyHeadersReceived(const URLRequest& request) {
  TRACE_EVENT0(kNetTracingCategory,
               "NetworkQualityEstimator::NotifyHeadersReceived");
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!RequestSchemeIsHTTPOrHTTPS(request) ||
      !RequestProvidesRTTObservation(request)) {
    return;
  }

  if (request.load_flags() & LOAD_MAIN_FRAME_DEPRECATED) {
    ComputeEffectiveConnectionType();
    RecordMetricsOnMainFrameRequest();
    MaybeQueryExternalEstimateProvider();
  }

  LoadTimingInfo load_timing_info;
  request.GetLoadTimingInfo(&load_timing_info);

  // If the load timing info is unavailable, it probably means that the request
  // did not go over the network.
  if (load_timing_info.send_start.is_null() ||
      load_timing_info.receive_headers_end.is_null()) {
    return;
  }
  DCHECK(!request.response_info().was_cached);

  // Duration between when the resource was requested and when the response
  // headers were received.
  base::TimeDelta observed_http_rtt =
      load_timing_info.receive_headers_end - load_timing_info.send_start;
  DCHECK_GE(observed_http_rtt, base::TimeDelta());
  if (observed_http_rtt < peak_network_quality_.http_rtt() ||
      peak_network_quality_.http_rtt() == nqe::internal::InvalidRTT()) {
    peak_network_quality_ = nqe::internal::NetworkQuality(
        observed_http_rtt, peak_network_quality_.transport_rtt(),
        peak_network_quality_.downstream_throughput_kbps());
  }

  RttObservation http_rtt_observation(
      observed_http_rtt, tick_clock_->NowTicks(), signal_strength_dbm_,
      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP);
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

  // Record the HTTP prediction accuracy for experimental statistics.
  for (int i = 0; i < STATISTIC_LAST; ++i) {
    recent_http_rtt = GetRTTEstimateInternal(
        disallowed_observation_sources_for_http_, last_main_frame_request_,
        static_cast<Statistic>(i), 50);
    if (recent_http_rtt != nqe::internal::InvalidRTT() &&
        http_rtt_at_last_main_frame_[i] != nqe::internal::InvalidRTT()) {
      int estimated_observed_diff_milliseconds =
          http_rtt_at_last_main_frame_[i].InMilliseconds() -
          recent_http_rtt.InMilliseconds();

      std::string histogram_name =
          base::StringPrintf("NQE.%s.Accuracy.HttpRTT", GetNameForStatistic(i));
      RecordRTTAccuracy(histogram_name, estimated_observed_diff_milliseconds,
                        measuring_duration, recent_http_rtt);
    }
  }

  if (!GetRecentHttpRTT(last_main_frame_request_, &recent_http_rtt))
    recent_http_rtt = nqe::internal::InvalidRTT();

  if (estimated_quality_at_last_main_frame_.http_rtt() !=
          nqe::internal::InvalidRTT() &&
      recent_http_rtt != nqe::internal::InvalidRTT()) {
    const int estimated_observed_diff_milliseconds =
        estimated_quality_at_last_main_frame_.http_rtt().InMilliseconds() -
        recent_http_rtt.InMilliseconds();

    RecordRTTAccuracy("NQE.Accuracy.HttpRTT",
                      estimated_observed_diff_milliseconds, measuring_duration,
                      recent_http_rtt);
  }

  base::TimeDelta recent_transport_rtt;
  if (estimated_quality_at_last_main_frame_.transport_rtt() !=
          nqe::internal::InvalidRTT() &&
      GetRecentTransportRTT(last_main_frame_request_, &recent_transport_rtt)) {
    const int estimated_observed_diff_milliseconds =
        estimated_quality_at_last_main_frame_.transport_rtt().InMilliseconds() -
        recent_transport_rtt.InMilliseconds();

    RecordRTTAccuracy("NQE.Accuracy.TransportRTT",
                      estimated_observed_diff_milliseconds, measuring_duration,
                      recent_transport_rtt);
  }

  int32_t recent_downstream_throughput_kbps;
  if (estimated_quality_at_last_main_frame_.downstream_throughput_kbps() !=
          nqe::internal::kInvalidThroughput &&
      GetRecentDownlinkThroughputKbps(last_main_frame_request_,
                                      &recent_downstream_throughput_kbps)) {
    const int estimated_observed_diff =
        estimated_quality_at_last_main_frame_.downstream_throughput_kbps() -
        recent_downstream_throughput_kbps;

    RecordThroughputAccuracy("NQE.Accuracy.DownstreamThroughputKbps",
                             estimated_observed_diff, measuring_duration,
                             recent_downstream_throughput_kbps);
  }

  EffectiveConnectionType recent_effective_connection_type =
      GetRecentEffectiveConnectionType(last_main_frame_request_);
  if (effective_connection_type_at_last_main_frame_ !=
          EFFECTIVE_CONNECTION_TYPE_UNKNOWN &&
      recent_effective_connection_type != EFFECTIVE_CONNECTION_TYPE_UNKNOWN) {
    const int estimated_observed_diff =
        static_cast<int>(effective_connection_type_at_last_main_frame_) -
        static_cast<int>(recent_effective_connection_type);

    RecordEffectiveConnectionTypeAccuracy(
        "NQE.Accuracy.EffectiveConnectionType", estimated_observed_diff,
        measuring_duration, recent_effective_connection_type);
  }

  // Add histogram to evaluate the accuracy of the external estimate provider.
  if (external_estimate_provider_quality_.http_rtt() !=
          nqe::internal::InvalidRTT() &&
      recent_http_rtt != nqe::internal::InvalidRTT()) {
    const int estimated_observed_diff_milliseconds =
        external_estimate_provider_quality_.http_rtt().InMilliseconds() -
        recent_http_rtt.InMilliseconds();

    RecordRTTAccuracy("NQE.ExternalEstimateProvider.RTT.Accuracy",
                      estimated_observed_diff_milliseconds, measuring_duration,
                      recent_http_rtt);
  }
}

void NetworkQualityEstimator::NotifyRequestCompleted(const URLRequest& request,
                                                     int net_error) {
  TRACE_EVENT0(kNetTracingCategory,
               "NetworkQualityEstimator::NotifyRequestCompleted");
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!RequestSchemeIsHTTPOrHTTPS(request))
    return;

  throughput_analyzer_->NotifyRequestCompleted(request);
  RecordCorrelationMetric(request, net_error);
}

void NetworkQualityEstimator::RecordCorrelationMetric(const URLRequest& request,
                                                      int net_error) const {
  DCHECK(thread_checker_.CalledOnValidThread());

  // The histogram is recorded randomly to reduce overhead involved with sparse
  // histograms. Furthermore, recording the correlation on each request is
  // unnecessary.
  if (RandDouble() >= params_.correlation_uma_logging_probability())
    return;

  if (request.response_info().was_cached ||
      !request.response_info().network_accessed) {
    return;
  }

  LoadTimingInfo load_timing_info;
  request.GetLoadTimingInfo(&load_timing_info);
  // If the load timing info is unavailable, it probably means that the request
  // did not go over the network.
  if (load_timing_info.send_start.is_null() ||
      load_timing_info.receive_headers_end.is_null()) {
    return;
  }

  // Record UMA only for successful requests that have completed.
  if (net_error != OK)
    return;
  if (!request.response_info().headers.get() ||
      request.response_info().headers->response_code() != HTTP_OK) {
    return;
  }
  if (load_timing_info.receive_headers_end < last_main_frame_request_)
    return;

  // Use the system clock instead of |tick_clock_| to compare the current
  // timestamp with the |load_timing_info| timestamp since the latter is set by
  // the system clock, and may be different from |tick_clock_| in tests.
  const base::TimeTicks now = base::TimeTicks::Now();
  // Record UMA only for requests that started recently.
  if (now - last_main_frame_request_ > base::TimeDelta::FromSeconds(15))
    return;

  if (last_connection_change_ >= last_main_frame_request_)
    return;

  DCHECK_GE(now, load_timing_info.send_start);

  int32_t rtt = 0;

  if (estimated_quality_at_last_main_frame_.downstream_throughput_kbps() ==
      nqe::internal::kInvalidThroughput) {
    return;
  }

  if (UseTransportRTT()) {
    if (estimated_quality_at_last_main_frame_.transport_rtt() ==
        nqe::internal::InvalidRTT()) {
      return;
    }
    rtt = FitInKBitsPerMetricBits(
        estimated_quality_at_last_main_frame_.transport_rtt().InMilliseconds());
  } else {
    if (estimated_quality_at_last_main_frame_.http_rtt() ==
        nqe::internal::InvalidRTT()) {
      return;
    }
    rtt = FitInKBitsPerMetricBits(
        estimated_quality_at_last_main_frame_.http_rtt().InMilliseconds());
  }

  const int32_t downstream_throughput = FitInKBitsPerMetricBits(
      estimated_quality_at_last_main_frame_.downstream_throughput_kbps());

  const int32_t resource_load_time = FitInKBitsPerMetricBits(
      (now - load_timing_info.send_start).InMilliseconds());

  int64_t resource_size = (request.GetTotalReceivedBytes() * 8) / 1024;
  if (resource_size >= (1 << kBitsPerMetric)) {
    // Too large resource size (at least 128 Kb).
    return;
  }

  DCHECK_EQ(
      0, (rtt | downstream_throughput | resource_load_time | resource_size) >>
             kBitsPerMetric);

  // First 32 - (4* kBitsPerMetric) of the sample are unset. Next
  // kBitsPerMetric of the sample contain |rtt|. Next
  // kBitsPerMetric contain |downstream_throughput|. Next kBitsPerMetric
  // contain |resource_load_time|. And, the last kBitsPerMetric
  // contain |resource_size|.
  int32_t sample = rtt;
  sample = (sample << kBitsPerMetric) | downstream_throughput;
  sample = (sample << kBitsPerMetric) | resource_load_time;
  sample = (sample << kBitsPerMetric) | resource_size;

  UMA_HISTOGRAM_SPARSE_SLOWLY("NQE.Correlation.ResourceLoadTime.0Kb_128Kb",
                              sample);
}

void NetworkQualityEstimator::NotifyURLRequestDestroyed(
    const URLRequest& request) {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!RequestSchemeIsHTTPOrHTTPS(request))
    return;

  throughput_analyzer_->NotifyRequestCompleted(request);
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

void NetworkQualityEstimator::DisableOfflineCheckForTesting(
    bool disable_offline_check) {
  DCHECK(thread_checker_.CalledOnValidThread());
  disable_offline_check_ = disable_offline_check;
  network_quality_store_->DisableOfflineCheckForTesting(disable_offline_check_);
}

void NetworkQualityEstimator::ReportEffectiveConnectionTypeForTesting(
    EffectiveConnectionType effective_connection_type) {
  DCHECK(thread_checker_.CalledOnValidThread());

  event_creator_.MaybeAddNetworkQualityChangedEventToNetLog(
      effective_connection_type_,
      params_.TypicalNetworkQuality(effective_connection_type));

  for (auto& observer : effective_connection_type_observer_list_)
    observer.OnEffectiveConnectionTypeChanged(effective_connection_type);

  network_quality_store_->Add(current_network_id_,
                              nqe::internal::CachedNetworkQuality(
                                  tick_clock_->NowTicks(), network_quality_,
                                  effective_connection_type));
}

void NetworkQualityEstimator::ReportRTTsAndThroughputForTesting(
    base::TimeDelta http_rtt,
    base::TimeDelta transport_rtt,
    int32_t downstream_throughput_kbps) {
  DCHECK(thread_checker_.CalledOnValidThread());

  for (auto& observer : rtt_and_throughput_estimates_observer_list_)
    observer.OnRTTOrThroughputEstimatesComputed(http_rtt, transport_rtt,
                                                downstream_throughput_kbps);
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
  network_quality_store_->Add(
      current_network_id_, nqe::internal::CachedNetworkQuality(
                               last_effective_connection_type_computation_,
                               network_quality_, effective_connection_type_));

  // Clear the local state.
  last_connection_change_ = tick_clock_->NowTicks();
  peak_network_quality_ = nqe::internal::NetworkQuality();
  downstream_throughput_kbps_observations_.Clear();
  rtt_observations_.Clear();

#if defined(OS_ANDROID)
  if (params_.weight_multiplier_per_dbm() < 1.0 &&
      NetworkChangeNotifier::IsConnectionCellular(current_network_id_.type)) {
    UMA_HISTOGRAM_BOOLEAN(
        "NQE.CellularSignalStrengthAvailable",
        min_signal_strength_since_connection_change_ != INT32_MAX &&
            max_signal_strength_since_connection_change_ != INT32_MIN);

    if (min_signal_strength_since_connection_change_ != INT32_MAX &&
        max_signal_strength_since_connection_change_ != INT32_MIN) {
      UMA_HISTOGRAM_COUNTS_100(
          "NQE.CellularSignalStrengthDifference",
          max_signal_strength_since_connection_change_ -
              min_signal_strength_since_connection_change_);
    }
  }
#endif  // OS_ANDROID
  signal_strength_dbm_ = INT32_MIN;
  min_signal_strength_since_connection_change_ = INT32_MAX;
  max_signal_strength_since_connection_change_ = INT32_MIN;
  network_quality_ = nqe::internal::NetworkQuality();
  effective_connection_type_ = EFFECTIVE_CONNECTION_TYPE_UNKNOWN;
  effective_connection_type_at_last_main_frame_ =
      EFFECTIVE_CONNECTION_TYPE_UNKNOWN;
  rtt_observations_size_at_last_ect_computation_ = 0;
  throughput_observations_size_at_last_ect_computation_ = 0;

  // Update the local state as part of preparation for the new connection.
  current_network_id_ = GetCurrentNetworkID();
  RecordNetworkIDAvailability();

  MaybeQueryExternalEstimateProvider();

  // Read any cached estimates for the new network. If cached estimates are
  // unavailable, add the default estimates.
  if (!ReadCachedNetworkQualityEstimate())
    AddDefaultEstimates();
  estimated_quality_at_last_main_frame_ = nqe::internal::NetworkQuality();

  for (int i = 0; i < STATISTIC_LAST; ++i)
    http_rtt_at_last_main_frame_[i] = nqe::internal::InvalidRTT();

  throughput_analyzer_->OnConnectionTypeChanged();
  MaybeComputeEffectiveConnectionType();
}

void NetworkQualityEstimator::MaybeQueryExternalEstimateProvider() const {
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
}

void NetworkQualityEstimator::UpdateSignalStrength() {
#if defined(OS_ANDROID)
  if (params_.weight_multiplier_per_dbm() >= 1.0 ||
      !NetworkChangeNotifier::IsConnectionCellular(current_network_id_.type) ||
      !android::cellular_signal_strength::GetSignalStrengthDbm(
          &signal_strength_dbm_)) {
    signal_strength_dbm_ = INT32_MIN;
  }
  min_signal_strength_since_connection_change_ = std::min(
      min_signal_strength_since_connection_change_, signal_strength_dbm_);
  max_signal_strength_since_connection_change_ = std::max(
      max_signal_strength_since_connection_change_, signal_strength_dbm_);
#endif  // OS_ANDROID
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
  if (GetRecentHttpRTT(base::TimeTicks(), &rtt)) {
    // Add the 50th percentile value.
    base::HistogramBase* rtt_percentile =
        GetHistogram("RTT.Percentile50.", current_network_id_.type, 10 * 1000);
    rtt_percentile->Add(rtt.InMilliseconds());

    // Add the remaining percentile values.
    static const int kPercentiles[] = {0, 10, 90, 100};
    for (size_t i = 0; i < arraysize(kPercentiles); ++i) {
      rtt = GetRTTEstimateInternal(
          disallowed_observation_sources_for_http_, base::TimeTicks(),
          base::Optional<Statistic>(), kPercentiles[i]);

      rtt_percentile = GetHistogram(
          "RTT.Percentile" + base::IntToString(kPercentiles[i]) + ".",
          current_network_id_.type, 10 * 1000);  // 10 seconds
      rtt_percentile->Add(rtt.InMilliseconds());
    }
  }

  if (GetRecentTransportRTT(base::TimeTicks(), &rtt)) {
    // Add the 50th percentile value.
    base::HistogramBase* transport_rtt_percentile = GetHistogram(
        "TransportRTT.Percentile50.", current_network_id_.type, 10 * 1000);
    transport_rtt_percentile->Add(rtt.InMilliseconds());

    // Add the remaining percentile values.
    static const int kPercentiles[] = {0, 10, 90, 100};
    for (size_t i = 0; i < arraysize(kPercentiles); ++i) {
      rtt = GetRTTEstimateInternal(
          disallowed_observation_sources_for_transport_, base::TimeTicks(),
          base::Optional<Statistic>(), kPercentiles[i]);

      transport_rtt_percentile = GetHistogram(
          "TransportRTT.Percentile" + base::IntToString(kPercentiles[i]) + ".",
          current_network_id_.type, 10 * 1000);  // 10 seconds
      transport_rtt_percentile->Add(rtt.InMilliseconds());
    }
  }
}

void NetworkQualityEstimator::RecordNetworkIDAvailability() const {
  DCHECK(thread_checker_.CalledOnValidThread());
  if (current_network_id_.type ==
          NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI ||
      NetworkChangeNotifier::IsConnectionCellular(current_network_id_.type)) {
    UMA_HISTOGRAM_BOOLEAN("NQE.NetworkIdAvailable",
                          !current_network_id_.id.empty());
  }
}

void NetworkQualityEstimator::RecordMetricsOnMainFrameRequest() const {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (estimated_quality_at_last_main_frame_.http_rtt() !=
      nqe::internal::InvalidRTT()) {
    // Add the 50th percentile value.
    UMA_HISTOGRAM_TIMES("NQE.MainFrame.RTT.Percentile50",
                        estimated_quality_at_last_main_frame_.http_rtt());
    base::HistogramBase* rtt_percentile = GetHistogram(
        "MainFrame.RTT.Percentile50.", current_network_id_.type, 10 * 1000);
    rtt_percentile->Add(
        estimated_quality_at_last_main_frame_.http_rtt().InMilliseconds());
  }
  UMA_HISTOGRAM_BOOLEAN("NQE.EstimateAvailable.MainFrame.RTT",
                        estimated_quality_at_last_main_frame_.http_rtt() !=
                            nqe::internal::InvalidRTT());

  if (estimated_quality_at_last_main_frame_.transport_rtt() !=
      nqe::internal::InvalidRTT()) {
    // Add the 50th percentile value.
    UMA_HISTOGRAM_TIMES("NQE.MainFrame.TransportRTT.Percentile50",
                        estimated_quality_at_last_main_frame_.transport_rtt());
    base::HistogramBase* transport_rtt_percentile =
        GetHistogram("MainFrame.TransportRTT.Percentile50.",
                     current_network_id_.type, 10 * 1000);
    transport_rtt_percentile->Add(
        estimated_quality_at_last_main_frame_.transport_rtt().InMilliseconds());
  }
  UMA_HISTOGRAM_BOOLEAN("NQE.EstimateAvailable.MainFrame.TransportRTT",
                        estimated_quality_at_last_main_frame_.transport_rtt() !=
                            nqe::internal::InvalidRTT());

  if (estimated_quality_at_last_main_frame_.downstream_throughput_kbps() !=
      nqe::internal::kInvalidThroughput) {
    // Add the 50th percentile value.
    UMA_HISTOGRAM_COUNTS_1M(
        "NQE.MainFrame.Kbps.Percentile50",
        estimated_quality_at_last_main_frame_.downstream_throughput_kbps());
    base::HistogramBase* throughput_percentile = GetHistogram(
        "MainFrame.Kbps.Percentile50.", current_network_id_.type, 1000 * 1000);
    throughput_percentile->Add(
        estimated_quality_at_last_main_frame_.downstream_throughput_kbps());
  }
  UMA_HISTOGRAM_BOOLEAN(
      "NQE.EstimateAvailable.MainFrame.Kbps",
      estimated_quality_at_last_main_frame_.downstream_throughput_kbps() !=
          nqe::internal::kInvalidThroughput);

  UMA_HISTOGRAM_ENUMERATION("NQE.MainFrame.EffectiveConnectionType",
                            effective_connection_type_at_last_main_frame_,
                            EFFECTIVE_CONNECTION_TYPE_LAST);
  base::HistogramBase* effective_connection_type_histogram =
      base::Histogram::FactoryGet(
          std::string("NQE.MainFrame.EffectiveConnectionType.") +
              nqe::internal::NetworkQualityEstimatorParams::
                  GetNameForConnectionType(current_network_id_.type),
          0, EFFECTIVE_CONNECTION_TYPE_LAST,
          EFFECTIVE_CONNECTION_TYPE_LAST /* Number of buckets */,
          base::HistogramBase::kUmaTargetedHistogramFlag);

  effective_connection_type_histogram->Add(
      effective_connection_type_at_last_main_frame_);

  // Record the HTTP RTT at the main frames for experimental statistics.
  for (int i = 0; i < STATISTIC_LAST; ++i) {
    if (http_rtt_at_last_main_frame_[i] != nqe::internal::InvalidRTT()) {
      base::HistogramBase* rtt_histogram = base::Histogram::FactoryGet(
          base::StringPrintf("NQE.%s.MainFrame.RTT", GetNameForStatistic(i)), 1,
          10 * 1000, 50, base::HistogramBase::kUmaTargetedHistogramFlag);
      rtt_histogram->Add(http_rtt_at_last_main_frame_[i].InMilliseconds());
    }
  }
}

void NetworkQualityEstimator::ComputeEffectiveConnectionType() {
  DCHECK(thread_checker_.CalledOnValidThread());

  UpdateSignalStrength();

  const base::TimeTicks now = tick_clock_->NowTicks();

  const EffectiveConnectionType past_type = effective_connection_type_;
  last_effective_connection_type_computation_ = now;

  base::TimeDelta http_rtt = nqe::internal::InvalidRTT();
  base::TimeDelta transport_rtt = nqe::internal::InvalidRTT();
  int32_t downstream_throughput_kbps = nqe::internal::kInvalidThroughput;

  effective_connection_type_ =
      GetRecentEffectiveConnectionTypeAndNetworkQuality(
          base::TimeTicks(), &http_rtt, &transport_rtt,
          &downstream_throughput_kbps);

  network_quality_ = nqe::internal::NetworkQuality(http_rtt, transport_rtt,
                                                   downstream_throughput_kbps);

  UMA_HISTOGRAM_ENUMERATION("NQE.EffectiveConnectionType.OnECTComputation",
                            effective_connection_type_,
                            EFFECTIVE_CONNECTION_TYPE_LAST);
  if (network_quality_.http_rtt() != nqe::internal::InvalidRTT()) {
    UMA_HISTOGRAM_TIMES("NQE.RTT.OnECTComputation",
                        network_quality_.http_rtt());
  }

  if (network_quality_.transport_rtt() != nqe::internal::InvalidRTT()) {
    UMA_HISTOGRAM_TIMES("NQE.TransportRTT.OnECTComputation",
                        network_quality_.transport_rtt());
  }

  if (network_quality_.downstream_throughput_kbps() !=
      nqe::internal::INVALID_RTT_THROUGHPUT) {
    UMA_HISTOGRAM_COUNTS_1M("NQE.Kbps.OnECTComputation",
                            network_quality_.downstream_throughput_kbps());
  }

  NotifyObserversOfRTTOrThroughputComputed();

  if (past_type != effective_connection_type_)
    NotifyObserversOfEffectiveConnectionTypeChanged();

  event_creator_.MaybeAddNetworkQualityChangedEventToNetLog(
      effective_connection_type_, network_quality_);

  rtt_observations_size_at_last_ect_computation_ = rtt_observations_.Size();
  throughput_observations_size_at_last_ect_computation_ =
      downstream_throughput_kbps_observations_.Size();
}

EffectiveConnectionType NetworkQualityEstimator::GetEffectiveConnectionType()
    const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return effective_connection_type_;
}

EffectiveConnectionType
NetworkQualityEstimator::GetRecentEffectiveConnectionType(
    const base::TimeTicks& start_time) const {
  DCHECK(thread_checker_.CalledOnValidThread());

  base::TimeDelta http_rtt = nqe::internal::InvalidRTT();
  base::TimeDelta transport_rtt = nqe::internal::InvalidRTT();
  int32_t downstream_throughput_kbps = nqe::internal::kInvalidThroughput;

  return GetRecentEffectiveConnectionTypeAndNetworkQuality(
      start_time, &http_rtt, &transport_rtt, &downstream_throughput_kbps);
}

EffectiveConnectionType
NetworkQualityEstimator::GetRecentEffectiveConnectionTypeAndNetworkQuality(
    const base::TimeTicks& start_time,
    base::TimeDelta* http_rtt,
    base::TimeDelta* transport_rtt,
    int32_t* downstream_throughput_kbps) const {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (effective_connection_type_algorithm_ ==
      EffectiveConnectionTypeAlgorithm::HTTP_RTT_AND_DOWNSTREAM_THROUGHOUT) {
    return GetRecentEffectiveConnectionTypeUsingMetrics(
        start_time, NetworkQualityEstimator::MetricUsage::
                        MUST_BE_USED /* http_rtt_metric */,
        NetworkQualityEstimator::MetricUsage::
            DO_NOT_USE /* transport_rtt_metric */,
        NetworkQualityEstimator::MetricUsage::
            USE_IF_AVAILABLE /* downstream_throughput_kbps_metric */,
        http_rtt, transport_rtt, downstream_throughput_kbps);
  }
  if (effective_connection_type_algorithm_ ==
      EffectiveConnectionTypeAlgorithm::
          TRANSPORT_RTT_OR_DOWNSTREAM_THROUGHOUT) {
    return GetRecentEffectiveConnectionTypeUsingMetrics(
        start_time,
        NetworkQualityEstimator::MetricUsage::DO_NOT_USE /* http_rtt_metric */,
        NetworkQualityEstimator::MetricUsage::
            USE_IF_AVAILABLE /* transport_rtt_metric */,
        NetworkQualityEstimator::MetricUsage::
            USE_IF_AVAILABLE /* downstream_throughput_kbps_metric */,
        http_rtt, transport_rtt, downstream_throughput_kbps);
  }
  // Add additional algorithms here.
  NOTREACHED();
  return EFFECTIVE_CONNECTION_TYPE_UNKNOWN;
}

bool NetworkQualityEstimator::UseTransportRTT() const {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (effective_connection_type_algorithm_ ==
      EffectiveConnectionTypeAlgorithm::HTTP_RTT_AND_DOWNSTREAM_THROUGHOUT) {
    return false;
  }
  if (effective_connection_type_algorithm_ ==
      EffectiveConnectionTypeAlgorithm::
          TRANSPORT_RTT_OR_DOWNSTREAM_THROUGHOUT) {
    return true;
  }
  // Add additional algorithms here.
  NOTREACHED();
  return false;
}

EffectiveConnectionType
NetworkQualityEstimator::GetRecentEffectiveConnectionTypeUsingMetrics(
    const base::TimeTicks& start_time,
    NetworkQualityEstimator::MetricUsage http_rtt_metric,
    NetworkQualityEstimator::MetricUsage transport_rtt_metric,
    NetworkQualityEstimator::MetricUsage downstream_throughput_kbps_metric,
    base::TimeDelta* http_rtt,
    base::TimeDelta* transport_rtt,
    int32_t* downstream_throughput_kbps) const {
  DCHECK(thread_checker_.CalledOnValidThread());

  *http_rtt = nqe::internal::InvalidRTT();
  *transport_rtt = nqe::internal::InvalidRTT();
  *downstream_throughput_kbps = nqe::internal::kInvalidThroughput;

  if (params_.forced_effective_connection_type()) {
    *http_rtt = params_
                    .TypicalNetworkQuality(
                        params_.forced_effective_connection_type().value())
                    .http_rtt();
    *transport_rtt = params_
                         .TypicalNetworkQuality(
                             params_.forced_effective_connection_type().value())
                         .transport_rtt();
    *downstream_throughput_kbps =
        params_
            .TypicalNetworkQuality(
                params_.forced_effective_connection_type().value())
            .downstream_throughput_kbps();
    return params_.forced_effective_connection_type().value();
  }

  // If the device is currently offline, then return
  // EFFECTIVE_CONNECTION_TYPE_OFFLINE.

  if (current_network_id_.type == NetworkChangeNotifier::CONNECTION_NONE &&
      !disable_offline_check_) {
    return EFFECTIVE_CONNECTION_TYPE_OFFLINE;
  }

  if (!GetRecentHttpRTT(start_time, http_rtt))
    *http_rtt = nqe::internal::InvalidRTT();

  if (!GetRecentTransportRTT(start_time, transport_rtt))
    *transport_rtt = nqe::internal::InvalidRTT();

  if (!GetRecentDownlinkThroughputKbps(start_time, downstream_throughput_kbps))
    *downstream_throughput_kbps = nqe::internal::kInvalidThroughput;

  if (*http_rtt == nqe::internal::InvalidRTT() &&
      http_rtt_metric == NetworkQualityEstimator::MetricUsage::MUST_BE_USED) {
    return EFFECTIVE_CONNECTION_TYPE_UNKNOWN;
  }

  if (*transport_rtt == nqe::internal::InvalidRTT() &&
      transport_rtt_metric ==
          NetworkQualityEstimator::MetricUsage::MUST_BE_USED) {
    return EFFECTIVE_CONNECTION_TYPE_UNKNOWN;
  }

  if (*downstream_throughput_kbps == nqe::internal::kInvalidThroughput &&
      downstream_throughput_kbps_metric ==
          NetworkQualityEstimator::MetricUsage::MUST_BE_USED) {
    return EFFECTIVE_CONNECTION_TYPE_UNKNOWN;
  }

  if (*http_rtt == nqe::internal::InvalidRTT() &&
      *transport_rtt == nqe::internal::InvalidRTT() &&
      *downstream_throughput_kbps == nqe::internal::kInvalidThroughput) {
    // None of the metrics are available.
    return EFFECTIVE_CONNECTION_TYPE_UNKNOWN;
  }

  // Search from the slowest connection type to the fastest to find the
  // EffectiveConnectionType that best matches the current connection's
  // performance. The match is done by comparing RTT and throughput.
  for (size_t i = 0; i < EFFECTIVE_CONNECTION_TYPE_LAST; ++i) {
    EffectiveConnectionType type = static_cast<EffectiveConnectionType>(i);
    if (i == EFFECTIVE_CONNECTION_TYPE_UNKNOWN)
      continue;

    const bool estimated_http_rtt_is_higher_than_threshold =
        http_rtt_metric != NetworkQualityEstimator::MetricUsage::DO_NOT_USE &&
        *http_rtt != nqe::internal::InvalidRTT() &&
        params_.ConnectionThreshold(type).http_rtt() !=
            nqe::internal::InvalidRTT() &&
        *http_rtt >= params_.ConnectionThreshold(type).http_rtt();

    const bool estimated_transport_rtt_is_higher_than_threshold =
        transport_rtt_metric !=
            NetworkQualityEstimator::MetricUsage::DO_NOT_USE &&
        *transport_rtt != nqe::internal::InvalidRTT() &&
        params_.ConnectionThreshold(type).transport_rtt() !=
            nqe::internal::InvalidRTT() &&
        *transport_rtt >= params_.ConnectionThreshold(type).transport_rtt();

    const bool estimated_throughput_is_lower_than_threshold =
        downstream_throughput_kbps_metric !=
            NetworkQualityEstimator::MetricUsage::DO_NOT_USE &&
        *downstream_throughput_kbps != nqe::internal::kInvalidThroughput &&
        params_.ConnectionThreshold(type).downstream_throughput_kbps() !=
            nqe::internal::kInvalidThroughput &&
        *downstream_throughput_kbps <=
            params_.ConnectionThreshold(type).downstream_throughput_kbps();

    if (estimated_http_rtt_is_higher_than_threshold ||
        estimated_transport_rtt_is_higher_than_threshold ||
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
  DCHECK(observer);
  effective_connection_type_observer_list_.AddObserver(observer);

  // Notify the |observer| on the next message pump since |observer| may not
  // be completely set up for receiving the callbacks.
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&NetworkQualityEstimator::
                                NotifyEffectiveConnectionTypeObserverIfPresent,
                            weak_ptr_factory_.GetWeakPtr(), observer));
}

void NetworkQualityEstimator::RemoveEffectiveConnectionTypeObserver(
    EffectiveConnectionTypeObserver* observer) {
  DCHECK(thread_checker_.CalledOnValidThread());
  effective_connection_type_observer_list_.RemoveObserver(observer);
}

void NetworkQualityEstimator::AddRTTAndThroughputEstimatesObserver(
    RTTAndThroughputEstimatesObserver* observer) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(observer);
  rtt_and_throughput_estimates_observer_list_.AddObserver(observer);

  // Notify the |observer| on the next message pump since |observer| may not
  // be completely set up for receiving the callbacks.
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(&NetworkQualityEstimator::
                     NotifyRTTAndThroughputEstimatesObserverIfPresent,
                 weak_ptr_factory_.GetWeakPtr(), observer));
}

void NetworkQualityEstimator::RemoveRTTAndThroughputEstimatesObserver(
    RTTAndThroughputEstimatesObserver* observer) {
  DCHECK(thread_checker_.CalledOnValidThread());
  rtt_and_throughput_estimates_observer_list_.RemoveObserver(observer);
}

bool NetworkQualityEstimator::GetRecentHttpRTT(
    const base::TimeTicks& start_time,
    base::TimeDelta* rtt) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  *rtt = GetRTTEstimateInternal(disallowed_observation_sources_for_http_,
                                start_time, base::Optional<Statistic>(), 50);
  return (*rtt != nqe::internal::InvalidRTT());
}

bool NetworkQualityEstimator::GetRecentTransportRTT(
    const base::TimeTicks& start_time,
    base::TimeDelta* rtt) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  *rtt = GetRTTEstimateInternal(disallowed_observation_sources_for_transport_,
                                start_time, base::Optional<Statistic>(), 50);
  return (*rtt != nqe::internal::InvalidRTT());
}

bool NetworkQualityEstimator::GetRecentDownlinkThroughputKbps(
    const base::TimeTicks& start_time,
    int32_t* kbps) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  *kbps = GetDownlinkThroughputKbpsEstimateInternal(start_time, 50);
  return (*kbps != nqe::internal::kInvalidThroughput);
}

base::TimeDelta NetworkQualityEstimator::GetRTTEstimateInternal(
    const std::vector<NetworkQualityObservationSource>&
        disallowed_observation_sources,
    base::TimeTicks start_time,
    const base::Optional<Statistic>& statistic,
    int percentile) const {
  DCHECK(thread_checker_.CalledOnValidThread());

  // RTT observations are sorted by duration from shortest to longest, thus
  // a higher percentile RTT will have a longer RTT than a lower percentile.
  base::TimeDelta rtt = nqe::internal::InvalidRTT();

  if (!statistic) {
    // Use default statistic algorithm.
    if (!rtt_observations_.GetPercentile(start_time, signal_strength_dbm_, &rtt,
                                         percentile,
                                         disallowed_observation_sources)) {
      return nqe::internal::InvalidRTT();
    }
    return rtt;
  }

  switch (statistic.value()) {
    case STATISTIC_LAST:
      NOTREACHED();
      return nqe::internal::InvalidRTT();
    case STATISTIC_WEIGHTED_AVERAGE:
      if (!rtt_observations_.GetWeightedAverage(
              start_time, signal_strength_dbm_, disallowed_observation_sources,
              &rtt)) {
        return nqe::internal::InvalidRTT();
      }
      return rtt;
    case STATISTIC_UNWEIGHTED_AVERAGE:
      if (!rtt_observations_.GetUnweightedAverage(
              start_time, signal_strength_dbm_, disallowed_observation_sources,
              &rtt)) {
        return nqe::internal::InvalidRTT();
      }
      return rtt;
  }
  NOTREACHED();
  return nqe::internal::InvalidRTT();
}

int32_t NetworkQualityEstimator::GetDownlinkThroughputKbpsEstimateInternal(
    const base::TimeTicks& start_time,
    int percentile) const {
  DCHECK(thread_checker_.CalledOnValidThread());

  // Throughput observations are sorted by kbps from slowest to fastest,
  // thus a higher percentile throughput will be faster than a lower one.
  int32_t kbps = nqe::internal::kInvalidThroughput;
  if (!downstream_throughput_kbps_observations_.GetPercentile(
          start_time, signal_strength_dbm_, &kbps, 100 - percentile,
          std::vector<NetworkQualityObservationSource>())) {
    return nqe::internal::kInvalidThroughput;
  }
  return kbps;
}

nqe::internal::NetworkID NetworkQualityEstimator::GetCurrentNetworkID() const {
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
    nqe::internal::NetworkID network_id(
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

  if (!params_.persistent_cache_reading_enabled())
    return false;

  nqe::internal::CachedNetworkQuality cached_network_quality;

  const bool cached_estimate_available = network_quality_store_->GetById(
      current_network_id_, &cached_network_quality);
  if (network_quality_store_->EligibleForCaching(current_network_id_)) {
    UMA_HISTOGRAM_BOOLEAN("NQE.CachedNetworkQualityAvailable",
                          cached_estimate_available);
  }

  if (!cached_estimate_available)
    return false;

  const base::TimeTicks now = tick_clock_->NowTicks();

  if (cached_network_quality.network_quality().downstream_throughput_kbps() !=
      nqe::internal::kInvalidThroughput) {
    ThroughputObservation througphput_observation(
        cached_network_quality.network_quality().downstream_throughput_kbps(),
        now, INT32_MIN,
        NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_CACHED_ESTIMATE);
    downstream_throughput_kbps_observations_.AddObservation(
        througphput_observation);
    NotifyObserversOfThroughput(througphput_observation);
  }

  if (cached_network_quality.network_quality().http_rtt() !=
      nqe::internal::InvalidRTT()) {
    RttObservation rtt_observation(
        cached_network_quality.network_quality().http_rtt(), now, INT32_MIN,
        NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_CACHED_ESTIMATE);
    rtt_observations_.AddObservation(rtt_observation);
    NotifyObserversOfRTT(rtt_observation);
  }

  if (cached_network_quality.network_quality().transport_rtt() !=
      nqe::internal::InvalidRTT()) {
    RttObservation rtt_observation(
        cached_network_quality.network_quality().transport_rtt(), now,
        INT32_MIN,
        NETWORK_QUALITY_OBSERVATION_SOURCE_TRANSPORT_CACHED_ESTIMATE);
    rtt_observations_.AddObservation(rtt_observation);
    NotifyObserversOfRTT(rtt_observation);
  }
  ComputeEffectiveConnectionType();
  return true;
}

void NetworkQualityEstimator::OnUpdatedEstimateAvailable(
    const base::TimeDelta& rtt,
    int32_t downstream_throughput_kbps,
    int32_t upstream_throughput_kbps) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(external_estimate_provider_);

  RecordExternalEstimateProviderMetrics(
      EXTERNAL_ESTIMATE_PROVIDER_STATUS_CALLBACK);

  external_estimate_provider_quality_ = nqe::internal::NetworkQuality();

  if (rtt > base::TimeDelta()) {
    RecordExternalEstimateProviderMetrics(
        EXTERNAL_ESTIMATE_PROVIDER_STATUS_RTT_AVAILABLE);
    UMA_HISTOGRAM_TIMES("NQE.ExternalEstimateProvider.RTT", rtt);
    RttObservation rtt_observation(
        rtt, tick_clock_->NowTicks(), signal_strength_dbm_,
        NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_EXTERNAL_ESTIMATE);
    rtt_observations_.AddObservation(rtt_observation);
    external_estimate_provider_quality_.set_http_rtt(rtt);
    NotifyObserversOfRTT(rtt_observation);
  }

  if (downstream_throughput_kbps > 0) {
    RecordExternalEstimateProviderMetrics(
        EXTERNAL_ESTIMATE_PROVIDER_STATUS_DOWNLINK_BANDWIDTH_AVAILABLE);
    UMA_HISTOGRAM_COUNTS("NQE.ExternalEstimateProvider.DownlinkBandwidth",
                         downstream_throughput_kbps);
    ThroughputObservation throughput_observation(
        downstream_throughput_kbps, tick_clock_->NowTicks(),
        signal_strength_dbm_,
        NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_EXTERNAL_ESTIMATE);
    downstream_throughput_kbps_observations_.AddObservation(
        throughput_observation);
    external_estimate_provider_quality_.set_downstream_throughput_kbps(
        downstream_throughput_kbps);
    NotifyObserversOfThroughput(throughput_observation);
  }
}

void NetworkQualityEstimator::SetTickClockForTesting(
    std::unique_ptr<base::TickClock> tick_clock) {
  DCHECK(thread_checker_.CalledOnValidThread());
  tick_clock_ = std::move(tick_clock);
}

double NetworkQualityEstimator::RandDouble() const {
  return base::RandDouble();
}

void NetworkQualityEstimator::OnUpdatedRTTAvailable(
    SocketPerformanceWatcherFactory::Protocol protocol,
    const base::TimeDelta& rtt) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_NE(nqe::internal::InvalidRTT(), rtt);

  RttObservation observation(rtt, tick_clock_->NowTicks(), signal_strength_dbm_,
                             ProtocolSourceToObservationSource(protocol));
  NotifyObserversOfRTT(observation);
  rtt_observations_.AddObservation(observation);
}

void NetworkQualityEstimator::NotifyObserversOfRTT(
    const RttObservation& observation) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_NE(nqe::internal::InvalidRTT(), observation.value);
  DCHECK_GT(NETWORK_QUALITY_OBSERVATION_SOURCE_MAX, observation.source);

  UMA_HISTOGRAM_ENUMERATION("NQE.RTT.ObservationSource", observation.source,
                            NETWORK_QUALITY_OBSERVATION_SOURCE_MAX);

  // Maybe recompute the effective connection type since a new RTT observation
  // is available.
  MaybeComputeEffectiveConnectionType();
  for (auto& observer : rtt_observer_list_) {
    observer.OnRTTObservation(observation.value.InMilliseconds(),
                              observation.timestamp, observation.source);
  }
}

void NetworkQualityEstimator::NotifyObserversOfThroughput(
    const ThroughputObservation& observation) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_NE(nqe::internal::kInvalidThroughput, observation.value);
  DCHECK_GT(NETWORK_QUALITY_OBSERVATION_SOURCE_MAX, observation.source);

  UMA_HISTOGRAM_ENUMERATION("NQE.Kbps.ObservationSource", observation.source,
                            NETWORK_QUALITY_OBSERVATION_SOURCE_MAX);

  // Maybe recompute the effective connection type since a new throughput
  // observation is available.
  MaybeComputeEffectiveConnectionType();
  for (auto& observer : throughput_observer_list_) {
    observer.OnThroughputObservation(observation.value, observation.timestamp,
                                     observation.source);
  }
}

void NetworkQualityEstimator::OnNewThroughputObservationAvailable(
    int32_t downstream_kbps) {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (downstream_kbps == 0)
    return;

  DCHECK_NE(nqe::internal::kInvalidThroughput, downstream_kbps);

  if (downstream_kbps > peak_network_quality_.downstream_throughput_kbps() ||
      peak_network_quality_.downstream_throughput_kbps() ==
          nqe::internal::kInvalidThroughput) {
    peak_network_quality_ = nqe::internal::NetworkQuality(
        peak_network_quality_.http_rtt(), peak_network_quality_.transport_rtt(),
        downstream_kbps);
  }
  ThroughputObservation throughput_observation(
      downstream_kbps, tick_clock_->NowTicks(), signal_strength_dbm_,
      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP);
  downstream_throughput_kbps_observations_.AddObservation(
      throughput_observation);
  NotifyObserversOfThroughput(throughput_observation);
}

void NetworkQualityEstimator::MaybeComputeEffectiveConnectionType() {
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
      last_connection_change_ < last_effective_connection_type_computation_ &&
      // Recompute the effective connection type if the previously computed
      // effective connection type was unknown.
      effective_connection_type_ != EFFECTIVE_CONNECTION_TYPE_UNKNOWN &&
      // Recompute the effective connection type if the number of samples
      // available now are 50% more than the number of samples that were
      // available when the effective connection type was last computed.
      rtt_observations_size_at_last_ect_computation_ * 1.5 >=
          rtt_observations_.Size() &&
      throughput_observations_size_at_last_ect_computation_ * 1.5 >=
          downstream_throughput_kbps_observations_.Size()) {
    return;
  }
  ComputeEffectiveConnectionType();
}

void NetworkQualityEstimator::
    NotifyObserversOfEffectiveConnectionTypeChanged() {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_NE(EFFECTIVE_CONNECTION_TYPE_LAST, effective_connection_type_);

  // TODO(tbansal): Add hysteresis in the notification.
  for (auto& observer : effective_connection_type_observer_list_)
    observer.OnEffectiveConnectionTypeChanged(effective_connection_type_);

  // Add the estimates of the current network to the cache store.
  if (effective_connection_type_ != EFFECTIVE_CONNECTION_TYPE_UNKNOWN) {
    network_quality_store_->Add(current_network_id_,
                                nqe::internal::CachedNetworkQuality(
                                    tick_clock_->NowTicks(), network_quality_,
                                    effective_connection_type_));
  }
}

void NetworkQualityEstimator::NotifyObserversOfRTTOrThroughputComputed() const {
  DCHECK(thread_checker_.CalledOnValidThread());

  // TODO(tbansal): Add hysteresis in the notification.
  for (auto& observer : rtt_and_throughput_estimates_observer_list_) {
    observer.OnRTTOrThroughputEstimatesComputed(
        network_quality_.http_rtt(), network_quality_.transport_rtt(),
        network_quality_.downstream_throughput_kbps());
  }
}

void NetworkQualityEstimator::NotifyEffectiveConnectionTypeObserverIfPresent(
    EffectiveConnectionTypeObserver* observer) const {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!effective_connection_type_observer_list_.HasObserver(observer))
    return;
  if (effective_connection_type_ == EFFECTIVE_CONNECTION_TYPE_UNKNOWN)
    return;
  observer->OnEffectiveConnectionTypeChanged(effective_connection_type_);
}

void NetworkQualityEstimator::NotifyRTTAndThroughputEstimatesObserverIfPresent(
    RTTAndThroughputEstimatesObserver* observer) const {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!rtt_and_throughput_estimates_observer_list_.HasObserver(observer))
    return;
  observer->OnRTTOrThroughputEstimatesComputed(
      network_quality_.http_rtt(), network_quality_.transport_rtt(),
      network_quality_.downstream_throughput_kbps());
}

void NetworkQualityEstimator::AddNetworkQualitiesCacheObserver(
    nqe::internal::NetworkQualityStore::NetworkQualitiesCacheObserver*
        observer) {
  DCHECK(thread_checker_.CalledOnValidThread());
  network_quality_store_->AddNetworkQualitiesCacheObserver(observer);
}

void NetworkQualityEstimator::RemoveNetworkQualitiesCacheObserver(
    nqe::internal::NetworkQualityStore::NetworkQualitiesCacheObserver*
        observer) {
  DCHECK(thread_checker_.CalledOnValidThread());
  network_quality_store_->RemoveNetworkQualitiesCacheObserver(observer);
}

void NetworkQualityEstimator::OnPrefsRead(
    const std::map<nqe::internal::NetworkID,
                   nqe::internal::CachedNetworkQuality> read_prefs) {
  DCHECK(thread_checker_.CalledOnValidThread());

  UMA_HISTOGRAM_COUNTS("NQE.Prefs.ReadSize", read_prefs.size());
  for (auto& it : read_prefs) {
    EffectiveConnectionType effective_connection_type =
        it.second.effective_connection_type();
    if (effective_connection_type == EFFECTIVE_CONNECTION_TYPE_UNKNOWN ||
        effective_connection_type == EFFECTIVE_CONNECTION_TYPE_OFFLINE) {
      continue;
    }

    // RTT and throughput values are not set in the prefs.
    DCHECK_EQ(nqe::internal::InvalidRTT(),
              it.second.network_quality().http_rtt());
    DCHECK_EQ(nqe::internal::InvalidRTT(),
              it.second.network_quality().transport_rtt());
    DCHECK_EQ(nqe::internal::kInvalidThroughput,
              it.second.network_quality().downstream_throughput_kbps());

    nqe::internal::CachedNetworkQuality cached_network_quality(
        base::TimeTicks::Now(),
        params_.TypicalNetworkQuality(effective_connection_type),
        effective_connection_type);

    network_quality_store_->Add(it.first, cached_network_quality);
    MaybeUpdateNetworkQualityFromCache(it.first, cached_network_quality);
  }
}

void NetworkQualityEstimator::MaybeUpdateNetworkQualityFromCache(
    const nqe::internal::NetworkID& network_id,
    const nqe::internal::CachedNetworkQuality& cached_network_quality) {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!params_.persistent_cache_reading_enabled())
    return;
  if (network_id != current_network_id_)
    return;

  // Since the cached network quality is for the current network, add it to
  // the current observations.
  RttObservation http_rtt_observation(
      cached_network_quality.network_quality().http_rtt(),
      base::TimeTicks::Now(), INT32_MIN,
      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_CACHED_ESTIMATE);
  rtt_observations_.AddObservation(http_rtt_observation);
  NotifyObserversOfRTT(http_rtt_observation);

  RttObservation transport_rtt_observation(
      cached_network_quality.network_quality().transport_rtt(),
      base::TimeTicks::Now(), INT32_MIN,
      NETWORK_QUALITY_OBSERVATION_SOURCE_TRANSPORT_CACHED_ESTIMATE);
  rtt_observations_.AddObservation(transport_rtt_observation);
  NotifyObserversOfRTT(transport_rtt_observation);

  // TODO(tbansal): crbug.com/673977: Remove this check.
  if (cached_network_quality.network_quality().downstream_throughput_kbps() !=
      nqe::internal::kInvalidThroughput) {
    ThroughputObservation throughput_observation(
        cached_network_quality.network_quality().downstream_throughput_kbps(),
        base::TimeTicks::Now(), INT32_MIN,
        NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_CACHED_ESTIMATE);
    downstream_throughput_kbps_observations_.AddObservation(
        throughput_observation);
    NotifyObserversOfThroughput(throughput_observation);
  }

  ComputeEffectiveConnectionType();
}

const char* NetworkQualityEstimator::GetNameForStatistic(int i) const {
  Statistic statistic = static_cast<Statistic>(i);
  switch (statistic) {
    case STATISTIC_WEIGHTED_AVERAGE:
      return "WeightedAverage";
    case STATISTIC_UNWEIGHTED_AVERAGE:
      return "UnweightedAverage";
    case STATISTIC_LAST:
      NOTREACHED();
      return "";
  }
  NOTREACHED();
  return "";
}

base::Optional<base::TimeDelta>
NetworkQualityEstimator::NetworkQualityProvider::GetHttpRTT() const {
  return base::Optional<base::TimeDelta>();
}

base::Optional<base::TimeDelta>
NetworkQualityEstimator::NetworkQualityProvider::GetTransportRTT() const {
  return base::Optional<base::TimeDelta>();
}

base::Optional<int32_t>
NetworkQualityEstimator::NetworkQualityProvider::GetDownstreamThroughputKbps()
    const {
  return base::Optional<int32_t>();
}

}  // namespace net

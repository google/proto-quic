// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_NETWORK_QUALITY_ESTIMATOR_H_
#define NET_NQE_NETWORK_QUALITY_ESTIMATOR_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <string>

#include "base/compiler_specific.h"
#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/observer_list.h"
#include "base/threading/thread_checker.h"
#include "base/time/time.h"
#include "net/base/net_export.h"
#include "net/base/network_change_notifier.h"
#include "net/nqe/cached_network_quality.h"
#include "net/nqe/effective_connection_type.h"
#include "net/nqe/event_creator.h"
#include "net/nqe/external_estimate_provider.h"
#include "net/nqe/network_id.h"
#include "net/nqe/network_quality.h"
#include "net/nqe/network_quality_observation.h"
#include "net/nqe/network_quality_observation_source.h"
#include "net/nqe/network_quality_store.h"
#include "net/nqe/observation_buffer.h"
#include "net/socket/socket_performance_watcher_factory.h"

namespace base {
class TickClock;
}  // namespace base

namespace net {

class NetLog;

namespace nqe {
namespace internal {
class ThroughputAnalyzer;
}
}

class URLRequest;

// NetworkQualityEstimator provides network quality estimates (quality of the
// full paths to all origins that have been connected to).
// The estimates are based on the observed organic traffic.
// A NetworkQualityEstimator instance is attached to URLRequestContexts and
// observes the traffic of URLRequests spawned from the URLRequestContexts.
// A single instance of NQE can be attached to multiple URLRequestContexts,
// thereby increasing the single NQE instance's accuracy by providing more
// observed traffic characteristics.
class NET_EXPORT NetworkQualityEstimator
    : public NetworkChangeNotifier::ConnectionTypeObserver,
      public ExternalEstimateProvider::UpdatedEstimateDelegate {
 public:
  // Observes changes in effective connection type.
  class NET_EXPORT EffectiveConnectionTypeObserver {
   public:
    // Notifies the observer of a change in the effective connection type.
    // NetworkQualityEstimator computes the effective connection type once in
    // every interval of duration
    // |effective_connection_type_recomputation_interval_|. Additionally, when
    // there is a change in the connection type of the device, then the
    // effective connection type is immediately recomputed. The observer must
    // register and unregister itself on the IO thread. All the observers would
    // be notified on the IO thread.
    //
    // If the computed effective connection type is different from the
    // previously notified effective connection type, then all the registered
    // observers are notified of the new effective connection type.
    virtual void OnEffectiveConnectionTypeChanged(
        EffectiveConnectionType type) = 0;

   protected:
    EffectiveConnectionTypeObserver() {}
    virtual ~EffectiveConnectionTypeObserver() {}

   private:
    DISALLOW_COPY_AND_ASSIGN(EffectiveConnectionTypeObserver);
  };

  // Observes changes in the network quality.
  class NET_EXPORT RTTAndThroughputEstimatesObserver {
   public:
    // Notifies the observer when estimated HTTP RTT, estimated transport RTT or
    // estimated downstream throughput is computed. NetworkQualityEstimator
    // computes the RTT and throughput estimates at regular intervals.
    // Additionally, when there is a change in the connection type of the
    // device, then the estimates are immediately computed. The observer must
    // register and unregister itself on the IO thread. All the observers would
    // be notified on the IO thread.
    //
    // |http_rtt|, |transport_rtt| and |downstream_throughput_kbps| are the
    // computed estimates of the HTTP RTT, transport RTT and downstream
    // throughput (in kilobits per second), respectively. If an estimate of the
    // HTTP or transport RTT is unavailable, it will be set to
    // nqe::internal::InvalidRTT(). If the throughput estimate is unavailable,
    // it will be set to nqe::internal::kInvalidThroughput.
    virtual void OnRTTOrThroughputEstimatesComputed(
        base::TimeDelta http_rtt,
        base::TimeDelta transport_rtt,
        int32_t downstream_throughput_kbps) = 0;

   protected:
    RTTAndThroughputEstimatesObserver() {}
    virtual ~RTTAndThroughputEstimatesObserver() {}

   private:
    DISALLOW_COPY_AND_ASSIGN(RTTAndThroughputEstimatesObserver);
  };

  // Observes measurements of round trip time.
  class NET_EXPORT_PRIVATE RTTObserver {
   public:
    // Will be called when a new RTT observation is available. The round trip
    // time is specified in milliseconds. The time when the observation was
    // taken and the source of the observation are provided.
    virtual void OnRTTObservation(int32_t rtt_ms,
                                  const base::TimeTicks& timestamp,
                                  NetworkQualityObservationSource source) = 0;

   protected:
    RTTObserver() {}
    virtual ~RTTObserver() {}

   private:
    DISALLOW_COPY_AND_ASSIGN(RTTObserver);
  };

  // Observes measurements of throughput.
  class NET_EXPORT_PRIVATE ThroughputObserver {
   public:
    // Will be called when a new throughput observation is available.
    // Throughput is specified in kilobits per second.
    virtual void OnThroughputObservation(
        int32_t throughput_kbps,
        const base::TimeTicks& timestamp,
        NetworkQualityObservationSource source) = 0;

   protected:
    ThroughputObserver() {}
    virtual ~ThroughputObserver() {}

   private:
    DISALLOW_COPY_AND_ASSIGN(ThroughputObserver);
  };

  // Provides simple interface to obtain the effective connection type.
  class NET_EXPORT NetworkQualityProvider {
   public:
    // Returns the current effective connection type.
    virtual EffectiveConnectionType GetEffectiveConnectionType() const = 0;

    // Adds |observer| to a list of effective connection type observers.
    virtual void AddEffectiveConnectionTypeObserver(
        EffectiveConnectionTypeObserver* observer) = 0;

    // Removes |observer| from a list of effective connection type observers.
    virtual void RemoveEffectiveConnectionTypeObserver(
        EffectiveConnectionTypeObserver* observer) = 0;

    virtual ~NetworkQualityProvider() {}

   protected:
    NetworkQualityProvider() {}

   private:
    DISALLOW_COPY_AND_ASSIGN(NetworkQualityProvider);
  };

  // Creates a new NetworkQualityEstimator.
  // |variation_params| is the map containing all field trial parameters
  // related to NetworkQualityEstimator field trial.
  // |external_estimates_provider| may be NULL. The caller must guarantee that
  // |net_log| outlives |this|.
  NetworkQualityEstimator(
      std::unique_ptr<ExternalEstimateProvider> external_estimates_provider,
      const std::map<std::string, std::string>& variation_params,
      NetLog* net_log);

  // Construct a NetworkQualityEstimator instance allowing for test
  // configuration. Registers for network type change notifications so estimates
  // can be kept network specific.
  // |external_estimates_provider| may be NULL.
  // |variation_params| is the map containing all field trial parameters for the
  // network quality estimator field trial.
  // |use_local_host_requests_for_tests| should only be true when testing
  // against local HTTP server and allows the requests to local host to be
  // used for network quality estimation.
  // |use_smaller_responses_for_tests| should only be true when testing.
  // Allows the responses smaller than |kMinTransferSizeInBits| to be used for
  // network quality estimation. The caller must guarantee that |net_log|
  // outlives |this|.
  NetworkQualityEstimator(
      std::unique_ptr<ExternalEstimateProvider> external_estimates_provider,
      const std::map<std::string, std::string>& variation_params,
      bool use_local_host_requests_for_tests,
      bool use_smaller_responses_for_tests,
      NetLog* net_log);

  ~NetworkQualityEstimator() override;

  // Returns the last computed effective type of the current connection. The
  // effective connection type is computed by the network quality estimator at
  // regular intervals and at certain events (e.g., connection change).
  // Virtualized for testing.
  virtual EffectiveConnectionType GetEffectiveConnectionType() const;

  // Returns the effective type of the current connection based on only the
  // samples observed after |start_time|. This should only be used for
  // recording the metrics. Virtualized for testing.
  virtual EffectiveConnectionType GetRecentEffectiveConnectionType(
      const base::TimeTicks& start_time) const;

  // Adds |observer| to the list of effective connection type observers. Must be
  // called on the IO thread. |observer| would be notified of the current
  // effective connection type in the next message pump.
  void AddEffectiveConnectionTypeObserver(
      EffectiveConnectionTypeObserver* observer);

  // Removes |observer| from the list of effective connection type observers.
  // Must be called on the IO thread.
  void RemoveEffectiveConnectionTypeObserver(
      EffectiveConnectionTypeObserver* observer);

  // Adds |observer| to the list of RTT and throughput estimate observers. Must
  // be called on the IO thread. |observer| would be notified of the current RTT
  // and throughput estimates in the next message pump.
  void AddRTTAndThroughputEstimatesObserver(
      RTTAndThroughputEstimatesObserver* observer);

  // Removes |observer| from the list of RTT and throughput estimate observers.
  // Must be called on the IO thread.
  void RemoveRTTAndThroughputEstimatesObserver(
      RTTAndThroughputEstimatesObserver* observer);

  // Notifies NetworkQualityEstimator that the response header of |request| has
  // been received.
  void NotifyHeadersReceived(const URLRequest& request);

  // Notifies NetworkQualityEstimator that the headers of |request| are about to
  // be sent.
  void NotifyStartTransaction(const URLRequest& request);

  // Notifies NetworkQualityEstimator that the response body of |request| has
  // been received.
  void NotifyRequestCompleted(const URLRequest& request, int net_error);

  // Notifies NetworkQualityEstimator that |request| will be destroyed.
  void NotifyURLRequestDestroyed(const URLRequest& request);

  // Adds |rtt_observer| to the list of round trip time observers. Must be
  // called on the IO thread.
  void AddRTTObserver(RTTObserver* rtt_observer);

  // Removes |rtt_observer| from the list of round trip time observers if it
  // is on the list of observers. Must be called on the IO thread.
  void RemoveRTTObserver(RTTObserver* rtt_observer);

  // Adds |throughput_observer| to the list of throughput observers. Must be
  // called on the IO thread.
  void AddThroughputObserver(ThroughputObserver* throughput_observer);

  // Removes |throughput_observer| from the list of throughput observers if it
  // is on the list of observers. Must be called on the IO thread.
  void RemoveThroughputObserver(ThroughputObserver* throughput_observer);

  SocketPerformanceWatcherFactory* GetSocketPerformanceWatcherFactory();

  // |use_localhost_requests| should only be true when testing against local
  // HTTP server and allows the requests to local host to be used for network
  // quality estimation.
  void SetUseLocalHostRequestsForTesting(bool use_localhost_requests);

  // |use_smaller_responses_for_tests| should only be true when testing.
  // Allows the responses smaller than |kMinTransferSizeInBits| to be used for
  // network quality estimation.
  void SetUseSmallResponsesForTesting(bool use_small_responses);

  // If |disable_offline_check| is set to true, then the device offline check is
  // disabled when computing the effective connection type or when writing the
  // prefs.
  void DisableOfflineCheckForTesting(bool disable_offline_check);

  // Reports |effective_connection_type| to all
  // EffectiveConnectionTypeObservers.
  void ReportEffectiveConnectionTypeForTesting(
      EffectiveConnectionType effective_connection_type);

  // Adds and removes |observer| from the list of cache observers.
  void AddNetworkQualitiesCacheObserver(
      nqe::internal::NetworkQualityStore::NetworkQualitiesCacheObserver*
          observer);
  void RemoveNetworkQualitiesCacheObserver(
      nqe::internal::NetworkQualityStore::NetworkQualitiesCacheObserver*
          observer);

  // Called when the persistent prefs have been read. |read_prefs| contains the
  // parsed prefs as a map between NetworkIDs and CachedNetworkQualities.
  void OnPrefsRead(
      const std::map<nqe::internal::NetworkID,
                     nqe::internal::CachedNetworkQuality> read_prefs);

 protected:
  // A protected constructor for testing that allows setting the value of
  // |add_default_platform_observations_|.
  NetworkQualityEstimator(
      std::unique_ptr<ExternalEstimateProvider> external_estimates_provider,
      const std::map<std::string, std::string>& variation_params,
      bool use_local_host_requests_for_tests,
      bool use_smaller_responses_for_tests,
      bool add_default_platform_observations,
      const NetLogWithSource& net_log);

  // NetworkChangeNotifier::ConnectionTypeObserver implementation:
  void OnConnectionTypeChanged(
      NetworkChangeNotifier::ConnectionType type) override;

  // ExternalEstimateProvider::UpdatedEstimateObserver implementation.
  void OnUpdatedEstimateAvailable(const base::TimeDelta& rtt,
                                  int32_t downstream_throughput_kbps,
                                  int32_t upstream_throughput_kbps) override;

  // Returns true if median RTT at the HTTP layer is available and sets |rtt|
  // to the median of RTT observations since |start_time|.
  // Virtualized for testing. |rtt| should not be null. The RTT at the HTTP
  // layer measures the time from when the request was sent (this happens after
  // the connection is established) to the time when the response headers were
  // received.
  // TODO(tbansal): Change it to return HTTP RTT as base::TimeDelta.
  virtual bool GetRecentHttpRTT(const base::TimeTicks& start_time,
                                base::TimeDelta* rtt) const WARN_UNUSED_RESULT;

  // Returns true if the median RTT at the transport layer is available and sets
  // |rtt| to the median of transport layer RTT observations since
  // |start_time|. |rtt| should not be null. Virtualized for testing.
  // TODO(tbansal): Change it to return transport RTT as base::TimeDelta.
  virtual bool GetRecentTransportRTT(const base::TimeTicks& start_time,
                                     base::TimeDelta* rtt) const
      WARN_UNUSED_RESULT;

  // Returns true if median downstream throughput is available and sets |kbps|
  // to the median of downstream throughput (in kilobits per second)
  // observations since |start_time|. Virtualized for testing. |kbps|
  // should not be null. Virtualized for testing.
  // TODO(tbansal): Change it to return throughput as int32.
  virtual bool GetRecentDownlinkThroughputKbps(
      const base::TimeTicks& start_time,
      int32_t* kbps) const WARN_UNUSED_RESULT;

  // Returns the list of intervals at which the accuracy of network quality
  // prediction should be recorded. Virtualized for testing.
  virtual const std::vector<base::TimeDelta>& GetAccuracyRecordingIntervals()
      const;

  // Overrides the tick clock used by |this| for testing.
  void SetTickClockForTesting(std::unique_ptr<base::TickClock> tick_clock);

  // Returns a random double in the range [0.0, 1.0). Virtualized for testing.
  virtual double RandDouble() const;

  // Returns the effective type of the current connection based on only the
  // observations received after |start_time|. |http_rtt|, |transport_rtt| and
  // |downstream_throughput_kbps| must be non-null. |http_rtt|, |transport_rtt|
  // and |downstream_throughput_kbps| are set to the expected HTTP RTT,
  // transport RTT and downstream throughput (in kilobits per second) based on
  // observations taken since |start_time|. Virtualized for testing.
  virtual EffectiveConnectionType
  GetRecentEffectiveConnectionTypeAndNetworkQuality(
      const base::TimeTicks& start_time,
      base::TimeDelta* http_rtt,
      base::TimeDelta* transport_rtt,
      int32_t* downstream_throughput_kbps) const;

  // Notifies |this| of a new transport layer RTT. Called by socket watchers.
  // Protected for testing.
  void OnUpdatedRTTAvailable(SocketPerformanceWatcherFactory::Protocol protocol,
                             const base::TimeDelta& rtt);

 private:
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest,
                           AdaptiveRecomputationEffectiveConnectionType);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, StoreObservations);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, TestAddObservation);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest,
                           DefaultObservationsOverridden);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest,
                           ObtainAlgorithmToUseFromParams);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, HalfLifeParam);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, ComputedPercentiles);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, TestGetMetricsSince);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest,
                           TestExternalEstimateProviderMergeEstimates);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest,
                           UnknownEffectiveConnectionType);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest,
                           TypicalNetworkQualities);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest,
                           OnPrefsReadWithReadingDisabled);

  // Value of round trip time observations is in base::TimeDelta.
  typedef nqe::internal::Observation<base::TimeDelta> RttObservation;
  typedef nqe::internal::ObservationBuffer<base::TimeDelta>
      RttObservationBuffer;

  // Value of throughput observations is in kilobits per second.
  typedef nqe::internal::Observation<int32_t> ThroughputObservation;
  typedef nqe::internal::ObservationBuffer<int32_t> ThroughputObservationBuffer;

  // Algorithms supported by network quality estimator for computing effective
  // connection type.
  enum class EffectiveConnectionTypeAlgorithm {
    HTTP_RTT_AND_DOWNSTREAM_THROUGHOUT = 0,
    TRANSPORT_RTT_OR_DOWNSTREAM_THROUGHOUT,
    EFFECTIVE_CONNECTION_TYPE_ALGORITHM_LAST
  };

  // Defines how a metric (e.g, transport RTT) should be used when computing
  // the effective connection type.
  enum class MetricUsage {
    // The metric should not be used when computing the effective connection
    // type.
    DO_NOT_USE = 0,
    // If the metric is available, then it should be used when computing the
    // effective connection type.
    USE_IF_AVAILABLE,
    // The metric is required when computing the effective connection type.
    // If the value of the metric is unavailable, effective connection type
    // should be set to |EFFECTIVE_CONNECTION_TYPE_UNKNOWN|.
    MUST_BE_USED,
  };

  // Map from algorithm names to EffectiveConnectionTypeAlgorithm.
  // TODO(tbansal): Consider using an autogenerated enum using macros.
  const std::map<std::string, EffectiveConnectionTypeAlgorithm>
      algorithm_name_to_enum_;

  // The default algorithm to be used if the algorithm value is not available
  // through field trial parameters.
  static const EffectiveConnectionTypeAlgorithm
      kDefaultEffectiveConnectionTypeAlgorithm =
          EffectiveConnectionTypeAlgorithm::HTTP_RTT_AND_DOWNSTREAM_THROUGHOUT;

  // Returns the RTT value to be used when the valid RTT is unavailable. Readers
  // should discard RTT if it is set to the value returned by |InvalidRTT()|.
  static const base::TimeDelta InvalidRTT();

  // Queries external estimate provider for network quality. When the network
  // quality is available, OnUpdatedEstimateAvailable() is called.
  void MaybeQueryExternalEstimateProvider() const;

  // Records UMA when there is a change in connection type.
  void RecordMetricsOnConnectionTypeChanged() const;

  // Records UMA on whether the NetworkID was available or not. Called right
  // after a network change event.
  void RecordNetworkIDAvailability() const;

  // Records UMA on main frame requests.
  void RecordMetricsOnMainFrameRequest() const;

  // Records a downstream throughput observation to the observation buffer if
  // a valid observation is available. |downstream_kbps| is the downstream
  // throughput in kilobits per second.
  void OnNewThroughputObservationAvailable(int32_t downstream_kbps);

  // Obtains the model parameters for different effective connection types from
  // the field trial parameters. For each effective connection type, a model
  // (currently composed of a RTT threshold and a downlink throughput threshold)
  // is provided by the field trial.
  void ObtainOperatingParams(
      const std::map<std::string, std::string>& variation_params);

  // Adds the default median RTT and downstream throughput estimate for the
  // current connection type to the observation buffer.
  void AddDefaultEstimates();

  // Returns an estimate of network quality at the specified |percentile|.
  // |disallowed_observation_sources| is the list of observation sources that
  // should be excluded when computing the percentile.
  // Only the observations later than |start_time| are taken into account.
  // |percentile| must be between 0 and 100 (both inclusive) with higher
  // percentiles indicating less performant networks. For example, if
  // |percentile| is 90, then the network is expected to be faster than the
  // returned estimate with 0.9 probability. Similarly, network is expected to
  // be slower than the returned estimate with 0.1 probability.
  base::TimeDelta GetRTTEstimateInternal(
      const std::vector<NetworkQualityObservationSource>&
          disallowed_observation_sources,
      const base::TimeTicks& start_time,
      int percentile) const;
  int32_t GetDownlinkThroughputKbpsEstimateInternal(
      const base::TimeTicks& start_time,
      int percentile) const;

  // Returns the current network ID checking by calling the platform APIs.
  // Virtualized for testing.
  virtual nqe::internal::NetworkID GetCurrentNetworkID() const;

  // Notifies RTT observers of |observation|. May also trigger recomputation
  // of effective connection type.
  void NotifyObserversOfRTT(const RttObservation& observation);

  // Notifies throughput observers of |observation|. May also trigger
  // recomputation of effective connection type.
  void NotifyObserversOfThroughput(const ThroughputObservation& observation);

  // Returns true only if the |request| can be used for RTT estimation.
  bool RequestProvidesRTTObservation(const URLRequest& request) const;

  // Recomputes effective connection type, if it was computed more than the
  // specified duration ago, or if there has been a connection change recently.
  void MaybeComputeEffectiveConnectionType();

  // Notifies observers of a change in effective connection type.
  void NotifyObserversOfEffectiveConnectionTypeChanged();

  // Notifies the observers of RTT or throughput estimates computation.
  void NotifyObserversOfRTTOrThroughputComputed() const;

  // Notifies |observer| of the current effective connection type if |observer|
  // is still registered as an observer.
  void NotifyEffectiveConnectionTypeObserverIfPresent(
      EffectiveConnectionTypeObserver* observer) const;

  // Notifies |observer| of the current RTT and throughput if |observer| is
  // still registered as an observer.
  void NotifyRTTAndThroughputEstimatesObserverIfPresent(
      RTTAndThroughputEstimatesObserver* observer) const;

  // Records NQE accuracy metrics. |measuring_duration| should belong to the
  // vector returned by AccuracyRecordingIntervals().
  // RecordAccuracyAfterMainFrame should be called |measuring_duration| after a
  // main frame request is observed.
  void RecordAccuracyAfterMainFrame(base::TimeDelta measuring_duration) const;

  // Obtains the current cellular signal strength value and updates
  // |min_signal_strength_since_connection_change_| and
  // |max_signal_strength_since_connection_change_|.
  void UpdateSignalStrength();

  // Returns the effective type of the current connection based on only the
  // samples observed after |start_time|. May use HTTP RTT, transport RTT and
  // downstream throughput to compute the effective connection type based on
  // |http_rtt_metric|, |transport_rtt_metric| and
  // |downstream_throughput_kbps_metric|, respectively. |http_rtt|,
  // |transport_rtt| and |downstream_throughput_kbps| must be non-null.
  // |http_rtt|, |transport_rtt| and |downstream_throughput_kbps| are
  // set to the expected HTTP RTT, transport RTT and downstream throughput (in
  // kilobits per second) based on observations taken since |start_time|.
  EffectiveConnectionType GetRecentEffectiveConnectionTypeUsingMetrics(
      const base::TimeTicks& start_time,
      MetricUsage http_rtt_metric,
      MetricUsage transport_rtt_metric,
      MetricUsage downstream_throughput_kbps_metric,
      base::TimeDelta* http_rtt,
      base::TimeDelta* transport_rtt,
      int32_t* downstream_throughput_kbps) const;

  // Values of external estimate provider status. This enum must remain
  // synchronized with the enum of the same name in
  // metrics/histograms/histograms.xml.
  enum NQEExternalEstimateProviderStatus {
    EXTERNAL_ESTIMATE_PROVIDER_STATUS_NOT_AVAILABLE,
    EXTERNAL_ESTIMATE_PROVIDER_STATUS_AVAILABLE,
    EXTERNAL_ESTIMATE_PROVIDER_STATUS_QUERIED,
    EXTERNAL_ESTIMATE_PROVIDER_STATUS_QUERY_SUCCESSFUL,
    EXTERNAL_ESTIMATE_PROVIDER_STATUS_CALLBACK,
    EXTERNAL_ESTIMATE_PROVIDER_STATUS_RTT_AVAILABLE,
    EXTERNAL_ESTIMATE_PROVIDER_STATUS_DOWNLINK_BANDWIDTH_AVAILABLE,
    EXTERNAL_ESTIMATE_PROVIDER_STATUS_BOUNDARY
  };

  // Records the metrics related to external estimate provider.
  void RecordExternalEstimateProviderMetrics(
      NQEExternalEstimateProviderStatus status) const;

  // Returns true if the cached network quality estimate was successfully read.
  bool ReadCachedNetworkQualityEstimate();

  // Records a correlation metric that can be used for computing the correlation
  // between HTTP-layer RTT, transport-layer RTT, throughput and the time
  // taken to complete |request|.
  void RecordCorrelationMetric(const URLRequest& request, int net_error) const;

  // Returns true if transport RTT should be used for computing the effective
  // connection type.
  bool UseTransportRTT() const;

  // Forces computation of effective connection type, and notifies observers
  // if there is a change in its value.
  void ComputeEffectiveConnectionType();

  // May update the network quality of the current network if |network_id|
  // matches the ID of the current network. |cached_network_quality| is the
  // cached network quality of the network with id |network_id|.
  void MaybeUpdateNetworkQualityFromCache(
      const nqe::internal::NetworkID& network_id,
      const nqe::internal::CachedNetworkQuality& cached_network_quality);

  // Determines if the requests to local host can be used in estimating the
  // network quality. Set to true only for tests.
  bool use_localhost_requests_;

  // Determines if the responses smaller than |kMinTransferSizeInBytes|
  // or shorter than |kMinTransferSizeInBytes| can be used in estimating the
  // network quality. Set to true only for tests.
  bool use_small_responses_;

  // When set to true, the device offline check is disabled when computing the
  // effective connection type or when writing the prefs.
  bool disable_offline_check_;

  // If true, default values provided by the platform are used for estimation.
  const bool add_default_platform_observations_;

  // The factor by which the weight of an observation reduces every second.
  const double weight_multiplier_per_second_;

  // The factor by which the weight of an observation reduces for every dBm
  // difference between the current signal strength (in dBm), and the signal
  // strength at the time when the observation was taken.
  const double weight_multiplier_per_dbm_;

  // Algorithm to use for computing effective connection type. The value is
  // obtained from field trial parameters. If the value from field trial
  // parameters is unavailable, it is set to
  // kDefaultEffectiveConnectionTypeAlgorithm.
  const EffectiveConnectionTypeAlgorithm effective_connection_type_algorithm_;

  // Tick clock used by the network quality estimator.
  std::unique_ptr<base::TickClock> tick_clock_;

  // Intervals after the main frame request arrives at which accuracy of network
  // quality prediction is recorded.
  std::vector<base::TimeDelta> accuracy_recording_intervals_;

  // Time when last connection change was observed.
  base::TimeTicks last_connection_change_;

  // ID of the current network.
  nqe::internal::NetworkID current_network_id_;

  // Peak network quality (fastest round-trip-time (RTT) and highest
  // downstream throughput) measured since last connectivity change. RTT is
  // measured from time the request is sent until the first byte received.
  // The accuracy is decreased by ignoring these factors:
  // 1) Multiple URLRequests can occur concurrently.
  // 2) Includes server processing time.
  nqe::internal::NetworkQuality peak_network_quality_;

  // Buffer that holds throughput observations (in kilobits per second) sorted
  // by timestamp.
  ThroughputObservationBuffer downstream_throughput_kbps_observations_;

  // Buffer that holds RTT observations sorted by timestamp.
  RttObservationBuffer rtt_observations_;

  // Default network quality observations obtained from the network quality
  // estimator field trial parameters. The observations are indexed by
  // ConnectionType.
  nqe::internal::NetworkQuality
      default_observations_[NetworkChangeNotifier::CONNECTION_LAST + 1];

  // Thresholds for different effective connection types obtained from field
  // trial variation params. These thresholds encode how different connection
  // types behave in general. In future, complex encodings (e.g., curve
  // fitting) may be used.
  nqe::internal::NetworkQuality connection_thresholds_
      [EffectiveConnectionType::EFFECTIVE_CONNECTION_TYPE_LAST];

  // Typical network quality for different effective connection types.
  nqe::internal::NetworkQuality typical_network_quality_
      [EffectiveConnectionType::EFFECTIVE_CONNECTION_TYPE_LAST];

  // Time when the transaction for the last main frame request was started.
  base::TimeTicks last_main_frame_request_;

  // Estimated network quality when the transaction for the last main frame
  // request was started.
  nqe::internal::NetworkQuality estimated_quality_at_last_main_frame_;
  EffectiveConnectionType effective_connection_type_at_last_main_frame_;

  // Estimated network quality obtained from external estimate provider when the
  // external estimate provider was last queried.
  nqe::internal::NetworkQuality external_estimate_provider_quality_;

  // ExternalEstimateProvider that provides network quality using operating
  // system APIs. May be NULL.
  const std::unique_ptr<ExternalEstimateProvider> external_estimate_provider_;

  // Observer list for changes in effective connection type.
  base::ObserverList<EffectiveConnectionTypeObserver>
      effective_connection_type_observer_list_;

  // Observer list for RTT or throughput estimates.
  base::ObserverList<RTTAndThroughputEstimatesObserver>
      rtt_and_throughput_estimates_observer_list_;

  // Observer lists for round trip times and throughput measurements.
  base::ObserverList<RTTObserver> rtt_observer_list_;
  base::ObserverList<ThroughputObserver> throughput_observer_list_;

  std::unique_ptr<SocketPerformanceWatcherFactory> watcher_factory_;

  // Takes throughput measurements, and passes them back to |this| through the
  // provided callback. |this| stores the throughput observations in
  // |downstream_throughput_kbps_observations_|, which are later used for
  // estimating the throughput.
  std::unique_ptr<nqe::internal::ThroughputAnalyzer> throughput_analyzer_;

  // Minimum duration between two consecutive computations of effective
  // connection type. Set to non-zero value as a performance optimization.
  const base::TimeDelta effective_connection_type_recomputation_interval_;

  // Time when the effective connection type was last computed.
  base::TimeTicks last_effective_connection_type_computation_;

  // Number of RTT and bandwidth samples available when effective connection
  // type was last recomputed.
  size_t rtt_observations_size_at_last_ect_computation_;
  size_t throughput_observations_size_at_last_ect_computation_;

  // Current estimate of the network quality.
  nqe::internal::NetworkQuality network_quality_;

  // Current effective connection type. It is updated on connection change
  // events. It is also updated every time there is network traffic (provided
  // the last computation was more than
  // |effective_connection_type_recomputation_interval_| ago).
  EffectiveConnectionType effective_connection_type_;

  // Last known value of the wireless signal strength. Set to INT32_MIN if
  // unavailable. |signal_strength_dbm_| is reset to INT32_MIN on connection
  // change events.
  int32_t signal_strength_dbm_;

  // Minimum and maximum signal strength (in dBm) observed since last connection
  // change. Updated on connection change and main frame requests.
  int32_t min_signal_strength_since_connection_change_;
  int32_t max_signal_strength_since_connection_change_;

  // It is costlier to add values to a sparse histogram. So, the correlation UMA
  // is recorded with |correlation_uma_logging_probability_| since recording it
  // in a sparse histogram for each request is unnecessary and cost-prohibitive.
  // e.g., if it is 0.0, then the UMA will never be recorded. On the other hand,
  // if it is 1.0, then it will be recorded for all valid HTTP requests.
  const double correlation_uma_logging_probability_;

  // Stores the qualities of different networks.
  std::unique_ptr<nqe::internal::NetworkQualityStore> network_quality_store_;

  // True if effective connection type value has been forced via variation
  // parameters. If set to true, GetEffectiveConnectionType() will always return
  // |forced_effective_connection_type_|.
  const bool forced_effective_connection_type_set_;
  const EffectiveConnectionType forced_effective_connection_type_;

  // Set to true if reading of the network quality prefs is enabled.
  const bool persistent_cache_reading_enabled_;

  base::ThreadChecker thread_checker_;

  // Manages the writing of events to the net log.
  nqe::internal::EventCreator event_creator_;

  // Vector that contains observation sources that should not be used when
  // computing the estimate at HTTP layer.
  const std::vector<NetworkQualityObservationSource>
      disallowed_observation_sources_for_http_;

  // Vector that contains observation sources that should not be used when
  // computing the estimate at transport layer.
  const std::vector<NetworkQualityObservationSource>
      disallowed_observation_sources_for_transport_;

  base::WeakPtrFactory<NetworkQualityEstimator> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(NetworkQualityEstimator);
};

}  // namespace net

#endif  // NET_NQE_NETWORK_QUALITY_ESTIMATOR_H_

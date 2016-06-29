// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_NETWORK_QUALITY_ESTIMATOR_H_
#define NET_NQE_NETWORK_QUALITY_ESTIMATOR_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <tuple>

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
#include "net/nqe/external_estimate_provider.h"
#include "net/nqe/network_quality.h"
#include "net/nqe/network_quality_observation.h"
#include "net/nqe/network_quality_observation_source.h"
#include "net/nqe/observation_buffer.h"
#include "net/socket/socket_performance_watcher_factory.h"

namespace base {
class TickClock;
}  // namespace base

namespace net {

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
class NET_EXPORT_PRIVATE NetworkQualityEstimator
    : public NetworkChangeNotifier::ConnectionTypeObserver,
      public ExternalEstimateProvider::UpdatedEstimateDelegate {
 public:
  // EffectiveConnectionType is the connection type whose typical performance is
  // most similar to the measured performance of the network in use. In many
  // cases, the "effective" connection type and the actual type of connection in
  // use are the same, but often a network connection performs significantly
  // different, usually worse, from its expected capabilities.
  // EffectiveConnectionType of a network is independent of if the current
  // connection is metered or not. For example, an unmetered slow connection may
  // have EFFECTIVE_CONNECTION_TYPE_SLOW_2G as its effective connection type.
  enum EffectiveConnectionType {
    // The connection types should be in increasing order of quality.
    EFFECTIVE_CONNECTION_TYPE_UNKNOWN = 0,
    EFFECTIVE_CONNECTION_TYPE_OFFLINE,
    EFFECTIVE_CONNECTION_TYPE_SLOW_2G,
    EFFECTIVE_CONNECTION_TYPE_2G,
    EFFECTIVE_CONNECTION_TYPE_3G,
    EFFECTIVE_CONNECTION_TYPE_4G,
    EFFECTIVE_CONNECTION_TYPE_BROADBAND,
    EFFECTIVE_CONNECTION_TYPE_LAST,
  };

  // Observes changes in effective connection type.
  class NET_EXPORT_PRIVATE EffectiveConnectionTypeObserver {
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

  // Creates a new NetworkQualityEstimator.
  // |variation_params| is the map containing all field trial parameters
  // related to NetworkQualityEstimator field trial.
  // |external_estimates_provider| may be NULL.
  NetworkQualityEstimator(
      std::unique_ptr<ExternalEstimateProvider> external_estimates_provider,
      const std::map<std::string, std::string>& variation_params);

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
  // network quality estimation.
  NetworkQualityEstimator(
      std::unique_ptr<ExternalEstimateProvider> external_estimates_provider,
      const std::map<std::string, std::string>& variation_params,
      bool use_local_host_requests_for_tests,
      bool use_smaller_responses_for_tests);

  ~NetworkQualityEstimator() override;

  // Returns the effective type of the current connection. Virtualized for
  // testing.
  virtual EffectiveConnectionType GetEffectiveConnectionType() const;

  // Returns the effective type of the current connection based on only the
  // samples observed after |start_time|. This should only be used for
  // recording the metrics. Virtualized for testing.
  virtual EffectiveConnectionType GetRecentEffectiveConnectionType(
      const base::TimeTicks& start_time) const;

  // Adds |observer| to the list of effective connection type observers. Must be
  // called on the IO thread.
  void AddEffectiveConnectionTypeObserver(
      EffectiveConnectionTypeObserver* observer);

  // Removes |observer| from the list of effective connection type observers.
  // Must be called on the IO thread.
  void RemoveEffectiveConnectionTypeObserver(
      EffectiveConnectionTypeObserver* observer);

  // Notifies NetworkQualityEstimator that the response header of |request| has
  // been received.
  void NotifyHeadersReceived(const URLRequest& request);

  // Notifies NetworkQualityEstimator that the headers of |request| are about to
  // be sent.
  void NotifyStartTransaction(const URLRequest& request);

  // Notifies NetworkQualityEstimator that the response body of |request| has
  // been received.
  void NotifyRequestCompleted(const URLRequest& request);

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

  // Returns a string equivalent to |type|.
  static const char* GetNameForEffectiveConnectionType(
      EffectiveConnectionType type);

  // Returns an EffectiveConnectionType equivalent to |connection_type_name|.
  static EffectiveConnectionType GetEffectiveConnectionTypeForName(
      const std::string& connection_type_name);

  // |use_localhost_requests| should only be true when testing against local
  // HTTP server and allows the requests to local host to be used for network
  // quality estimation.
  void SetUseLocalHostRequestsForTesting(bool use_localhost_requests);

  // |use_smaller_responses_for_tests| should only be true when testing.
  // Allows the responses smaller than |kMinTransferSizeInBits| to be used for
  // network quality estimation.
  void SetUseSmallResponsesForTesting(bool use_small_responses);

 protected:
  // NetworkID is used to uniquely identify a network.
  // For the purpose of network quality estimation and caching, a network is
  // uniquely identified by a combination of |type| and
  // |id|. This approach is unable to distinguish networks with
  // same name (e.g., different Wi-Fi networks with same SSID).
  // This is a protected member to expose it to tests.
  struct NET_EXPORT_PRIVATE NetworkID {
    NetworkID(NetworkChangeNotifier::ConnectionType type, const std::string& id)
        : type(type), id(id) {}
    NetworkID(const NetworkID& other) : type(other.type), id(other.id) {}
    ~NetworkID() {}

    NetworkID& operator=(const NetworkID& other) {
      type = other.type;
      id = other.id;
      return *this;
    }

    // Overloaded because NetworkID is used as key in a map.
    bool operator<(const NetworkID& other) const {
      return std::tie(type, id) < std::tie(other.type, other.id);
    }

    // Connection type of the network.
    NetworkChangeNotifier::ConnectionType type;

    // Name of this network. This is set to:
    // - Wi-Fi SSID if the device is connected to a Wi-Fi access point and the
    //   SSID name is available, or
    // - MCC/MNC code of the cellular carrier if the device is connected to a
    //   cellular network, or
    // - "Ethernet" in case the device is connected to ethernet.
    // - An empty string in all other cases or if the network name is not
    //   exposed by platform APIs.
    std::string id;
  };

  // Returns true if the cached network quality estimate was successfully read.
  bool ReadCachedNetworkQualityEstimate();

  // NetworkChangeNotifier::ConnectionTypeObserver implementation:
  void OnConnectionTypeChanged(
      NetworkChangeNotifier::ConnectionType type) override;

  // ExternalEstimateProvider::UpdatedEstimateObserver implementation.
  void OnUpdatedEstimateAvailable(const base::TimeDelta& rtt,
                                  int32_t downstream_throughput_kbps,
                                  int32_t upstream_throughput_kbps) override;

  // Returns true if the RTT is available and sets |rtt| to the RTT estimated at
  // the HTTP layer. Virtualized for testing. |rtt| should not be null. The RTT
  // at the HTTP layer measures the time from when the request was sent (this
  // happens after the connection is established) to the time when the response
  // headers were received.
  virtual bool GetHttpRTTEstimate(base::TimeDelta* rtt) const
      WARN_UNUSED_RESULT;

  // Returns true if the RTT is available and sets |rtt| to the RTT estimated at
  // the transport layer. |rtt| should not be null. Virtualized for testing.
  virtual bool GetTransportRTTEstimate(base::TimeDelta* rtt) const
      WARN_UNUSED_RESULT;

  // Returns true if downlink throughput is available and sets |kbps| to
  // estimated downlink throughput (in kilobits per second).
  // Virtualized for testing. |kbps| should not be null.
  virtual bool GetDownlinkThroughputKbpsEstimate(int32_t* kbps) const;

  // Returns true if median RTT at the HTTP layer is available and sets |rtt|
  // to the median of RTT observations since |start_time|.
  // Virtualized for testing. |rtt| should not be null. The RTT at the HTTP
  // layer measures the time from when the request was sent (this happens after
  // the connection is established) to the time when the response headers were
  // received.
  virtual bool GetRecentHttpRTTMedian(const base::TimeTicks& start_time,
                                      base::TimeDelta* rtt) const
      WARN_UNUSED_RESULT;

  // Returns true if the median RTT at the transport layer is available and sets
  // |rtt| to the median of transport layer RTT observations since
  // |start_time|. |rtt| should not be null. Virtualized for testing.
  virtual bool GetRecentTransportRTTMedian(const base::TimeTicks& start_time,
                                           base::TimeDelta* rtt) const
      WARN_UNUSED_RESULT;

  // Returns true if median downstream throughput is available and sets |kbps|
  // to the median of downstream throughput (in kilobits per second)
  // observations since |start_time|. Virtualized for testing. |kbps|
  // should not be null. Virtualized for testing.
  virtual bool GetRecentMedianDownlinkThroughputKbps(
      const base::TimeTicks& start_time,
      int32_t* kbps) const WARN_UNUSED_RESULT;

  // Returns the list of intervals at which the accuracy of network quality
  // prediction should be recorded. Virtualized for testing.
  virtual const std::vector<base::TimeDelta>& GetAccuracyRecordingIntervals()
      const;

  // Overrides the tick clock used by |this| for testing.
  void SetTickClockForTesting(std::unique_ptr<base::TickClock> tick_clock);

 private:
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, StoreObservations);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, TestAddObservation);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, ObtainOperatingParams);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest,
                           ObtainAlgorithmToUseFromParams);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, HalfLifeParam);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, ComputedPercentiles);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, TestCaching);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest,
                           TestLRUCacheMaximumSize);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, TestGetMetricsSince);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest,
                           TestExternalEstimateProviderMergeEstimates);

  // Value of round trip time observations is in base::TimeDelta.
  typedef nqe::internal::Observation<base::TimeDelta> RttObservation;
  typedef nqe::internal::ObservationBuffer<base::TimeDelta>
      RttObservationBuffer;

  // Value of throughput observations is in kilobits per second.
  typedef nqe::internal::Observation<int32_t> ThroughputObservation;
  typedef nqe::internal::ObservationBuffer<int32_t> ThroughputObservationBuffer;

  // This does not use a unordered_map or hash_map for code simplicity (key just
  // implements operator<, rather than hash and equality) and because the map is
  // tiny.
  typedef std::map<NetworkID, nqe::internal::CachedNetworkQuality>
      CachedNetworkQualities;

  // Algorithms supported by network quality estimator for computing effective
  // connection type.
  enum class EffectiveConnectionTypeAlgorithm {
    HTTP_RTT_AND_DOWNSTREAM_THROUGHOUT = 0,
    EFFECTIVE_CONNECTION_TYPE_ALGORITHM_LAST
  };

  // Map from algorithm names to EffectiveConnectionTypeAlgorithm.
  const std::map<std::string, EffectiveConnectionTypeAlgorithm>
      algorithm_name_to_enum_;

  // The default algorithm to be used if the algorithm value is not available
  // through field trial parameters.
  static const EffectiveConnectionTypeAlgorithm
      kDefaultEffectiveConnectionTypeAlgorithm =
          EffectiveConnectionTypeAlgorithm::HTTP_RTT_AND_DOWNSTREAM_THROUGHOUT;

  // Minimum valid value of the variation parameter that holds RTT (in
  // milliseconds) values.
  static const int kMinimumRTTVariationParameterMsec = 1;

  // Minimum valid value of the variation parameter that holds throughput (in
  // kilobits per second) values.
  static const int kMinimumThroughputVariationParameterKbps = 1;

  // Maximum size of the cache that holds network quality estimates.
  // Smaller size may reduce the cache hit rate due to frequent evictions.
  // Larger size may affect performance.
  static const size_t kMaximumNetworkQualityCacheSize = 10;

  // Returns the RTT value to be used when the valid RTT is unavailable. Readers
  // should discard RTT if it is set to the value returned by |InvalidRTT()|.
  static const base::TimeDelta InvalidRTT();

  // Records UMA when there is a change in connection type.
  void RecordMetricsOnConnectionTypeChanged() const;

  // Records UMA on main frame requests.
  void RecordMetricsOnMainFrameRequest() const;

  // Records a downstream throughput observation to the observation buffer if
  // a valid observation is available. |downstream_kbps| is the downstream
  // throughput in kilobits per second.
  void OnNewThroughputObservationAvailable(int32_t downstream_kbps);

  // Notifies |this| of a new transport layer RTT.
  void OnUpdatedRTTAvailable(SocketPerformanceWatcherFactory::Protocol protocol,
                             const base::TimeDelta& rtt);

  // Obtains operating parameters from the field trial parameters.
  void ObtainOperatingParams(
      const std::map<std::string, std::string>& variation_params);

  // Obtains the model parameters for different effective connection types from
  // the field trial parameters. For each effective connection type, a model
  // (currently composed of a RTT threshold and a downlink throughput threshold)
  // is provided by the field trial.
  void ObtainEffectiveConnectionTypeModelParams(
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
  virtual NetworkID GetCurrentNetworkID() const;

  // Writes the estimated quality of the current network to the cache.
  void CacheNetworkQualityEstimate();

  void NotifyObserversOfRTT(const RttObservation& observation);

  void NotifyObserversOfThroughput(const ThroughputObservation& observation);

  // Returns true only if the |request| can be used for RTT estimation.
  bool RequestProvidesRTTObservation(const URLRequest& request) const;

  // Recomputes effective connection type, if it was computed more than the
  // specified duration ago, or if there has been a connection change recently.
  void MaybeRecomputeEffectiveConnectionType();

  // Notify observers of a change in effective connection type.
  void NotifyObserversOfEffectiveConnectionTypeChanged();

  // Records NQE accuracy metrics. |measuring_duration| should belong to the
  // vector returned by AccuracyRecordingIntervals().
  // RecordAccuracyAfterMainFrame should be called |measuring_duration| after a
  // main frame request is observed.
  void RecordAccuracyAfterMainFrame(base::TimeDelta measuring_duration) const;

  // Returns the effective type of the current connection based on only the
  // samples observed after |start_time|. Uses HTTP RTT and downstream
  // throughput to compute the effective connection type, and requires both of
  // them to have a valid value.
  EffectiveConnectionType
  GetRecentEffectiveConnectionTypeHttpRTTAndDownstreamThroughput(
      const base::TimeTicks& start_time) const;

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

  // Determines if the requests to local host can be used in estimating the
  // network quality. Set to true only for tests.
  bool use_localhost_requests_;

  // Determines if the responses smaller than |kMinTransferSizeInBytes|
  // or shorter than |kMinTransferSizeInBytes| can be used in estimating the
  // network quality. Set to true only for tests.
  bool use_small_responses_;

  // The factor by which the weight of an observation reduces every second.
  const double weight_multiplier_per_second_;

  // Algorithm to use for computing effective connection type. The value is
  // obtained from field trial parameters. If the value from field trial
  // parameters is unavailable, it is set to
  // kDefaultEffectiveConnectionTypeAlgorithm.
  const EffectiveConnectionTypeAlgorithm effective_connection_type_algorithm_;

  // Tick clock used by the network quality estimator.
  std::unique_ptr<base::TickClock> tick_clock_;

  // Minimum duration between two consecutive computations of effective
  // connection type. Set to non-zero value as a performance optimization.
  const base::TimeDelta effective_connection_type_recomputation_interval_;

  // Time when the effective connection type was last computed.
  base::TimeTicks last_effective_connection_type_computation_;

  // Intervals after the main frame request arrives at which accuracy of network
  // quality prediction is recorded.
  std::vector<base::TimeDelta> accuracy_recording_intervals_;

  // Time when last connection change was observed.
  base::TimeTicks last_connection_change_;

  // ID of the current network.
  NetworkID current_network_id_;

  // Peak network quality (fastest round-trip-time (RTT) and highest
  // downstream throughput) measured since last connectivity change. RTT is
  // measured from time the request is sent until the first byte received.
  // The accuracy is decreased by ignoring these factors:
  // 1) Multiple URLRequests can occur concurrently.
  // 2) Includes server processing time.
  nqe::internal::NetworkQuality peak_network_quality_;

  // Cache that stores quality of previously seen networks.
  CachedNetworkQualities cached_network_qualities_;

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
  nqe::internal::NetworkQuality
      connection_thresholds_[EFFECTIVE_CONNECTION_TYPE_LAST];

  // Latest time when the headers for a main frame request were received.
  base::TimeTicks last_main_frame_request_;

  // Estimated network quality when the response headers for the last mainframe
  // request were received.
  nqe::internal::NetworkQuality estimated_quality_at_last_main_frame_;
  EffectiveConnectionType effective_connection_type_at_last_main_frame_;

  // ExternalEstimateProvider that provides network quality using operating
  // system APIs. May be NULL.
  const std::unique_ptr<ExternalEstimateProvider> external_estimate_provider_;

  // Observer list for changes in effective connection type.
  base::ObserverList<EffectiveConnectionTypeObserver>
      effective_connection_type_observer_list_;

  // Observer lists for round trip times and throughput measurements.
  base::ObserverList<RTTObserver> rtt_observer_list_;
  base::ObserverList<ThroughputObserver> throughput_observer_list_;

  std::unique_ptr<SocketPerformanceWatcherFactory> watcher_factory_;

  // Takes throughput measurements, and passes them back to |this| through the
  // provided callback. |this| stores the throughput observations in
  // |downstream_throughput_kbps_observations_|, which are later used for
  // estimating the throughput.
  std::unique_ptr<nqe::internal::ThroughputAnalyzer> throughput_analyzer_;

  // Current effective connection type. It is updated on connection change
  // events. It is also updated every time there is network traffic (provided
  // the last computation was more than
  // |effective_connection_type_recomputation_interval_| ago).
  EffectiveConnectionType effective_connection_type_;

  base::ThreadChecker thread_checker_;

  base::WeakPtrFactory<NetworkQualityEstimator> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(NetworkQualityEstimator);
};

}  // namespace net

#endif  // NET_NQE_NETWORK_QUALITY_ESTIMATOR_H_

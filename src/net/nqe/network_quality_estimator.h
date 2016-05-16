// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_NETWORK_QUALITY_ESTIMATOR_H_
#define NET_NQE_NETWORK_QUALITY_ESTIMATOR_H_

#include <stddef.h>
#include <stdint.h>

#include <deque>
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
#include "net/nqe/external_estimate_provider.h"
#include "net/socket/socket_performance_watcher_factory.h"

namespace base {
class SingleThreadTaskRunner;
}  // namespace base

namespace net {

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

  // On Android, a Java counterpart will be generated for this enum.
  // GENERATED_JAVA_ENUM_PACKAGE: org.chromium.net
  // GENERATED_JAVA_CLASS_NAME_OVERRIDE: NetworkQualityObservationSource
  // GENERATED_JAVA_PREFIX_TO_STRIP:
  enum ObservationSource {
    // The observation was taken at the request layer, e.g., a round trip time
    // is recorded as the time between the request being sent and the first byte
    // being received.
    URL_REQUEST,
    // The observation is taken from TCP statistics maintained by the kernel.
    TCP,
    // The observation is taken at the QUIC layer.
    QUIC,
    // The observation is a previously cached estimate of the metric.
    CACHED_ESTIMATE,
    // The observation is derived from network connection information provided
    // by the platform. For example, typical RTT and throughput values are used
    // for a given type of network connection.
    DEFAULT_FROM_PLATFORM,
    // The observation came from a Chromium-external source.
    EXTERNAL_ESTIMATE
  };

  // Observes measurements of round trip time.
  class NET_EXPORT_PRIVATE RTTObserver {
   public:
    // Will be called when a new RTT observation is available. The round trip
    // time is specified in milliseconds. The time when the observation was
    // taken and the source of the observation are provided.
    virtual void OnRTTObservation(int32_t rtt_ms,
                                  const base::TimeTicks& timestamp,
                                  ObservationSource source) = 0;

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
    virtual void OnThroughputObservation(int32_t throughput_kbps,
                                         const base::TimeTicks& timestamp,
                                         ObservationSource source) = 0;

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
  // |allow_local_host_requests_for_tests| should only be true when testing
  // against local HTTP server and allows the requests to local host to be
  // used for network quality estimation.
  // |allow_smaller_responses_for_tests| should only be true when testing.
  // Allows the responses smaller than |kMinTransferSizeInBytes| or shorter than
  // |kMinRequestDurationMicroseconds| to be used for network quality
  // estimation.
  NetworkQualityEstimator(
      std::unique_ptr<ExternalEstimateProvider> external_estimates_provider,
      const std::map<std::string, std::string>& variation_params,
      bool allow_local_host_requests_for_tests,
      bool allow_smaller_responses_for_tests);

  ~NetworkQualityEstimator() override;

  // Returns the effective type of the current connection. Virtualized for
  // testing.
  virtual EffectiveConnectionType GetEffectiveConnectionType() const;

  // Returns true if RTT is available and sets |rtt| to estimated RTT at the
  // HTTP layer. Virtualized for testing. |rtt| should not be null. The RTT at
  // the HTTP layer measures the time from when the request was sent (this
  // happens after the connection is established) to the time when the response
  // headers were received.
  virtual bool GetURLRequestRTTEstimate(base::TimeDelta* rtt) const
      WARN_UNUSED_RESULT;

  // Returns true if downlink throughput is available and sets |kbps| to
  // estimated downlink throughput (in kilobits per second).
  // Virtualized for testing. |kbps| should not be null.
  virtual bool GetDownlinkThroughputKbpsEstimate(int32_t* kbps) const;

  // Notifies NetworkQualityEstimator that the response header of |request| has
  // been received.
  void NotifyHeadersReceived(const URLRequest& request);

  // Notifies NetworkQualityEstimator that the response body of |request| has
  // been received.
  void NotifyRequestCompleted(const URLRequest& request);

  // Returns true if median RTT at the HTTP layer is available and sets |rtt|
  // to the median of RTT observations since |begin_timestamp|.
  // Virtualized for testing. |rtt| should not be null. The RTT at the HTTP
  // layer measures the time from when the request was sent (this happens after
  // the connection is established) to the time when the response headers were
  // received.
  virtual bool GetRecentURLRequestRTTMedian(
      const base::TimeTicks& begin_timestamp,
      base::TimeDelta* rtt) const WARN_UNUSED_RESULT;

  // Returns true if median downstream throughput is available and sets |kbps|
  // to the median of downstream throughput (in kilobits per second)
  // observations since |begin_timestamp|. Virtualized for testing. |kbps|
  // should not be null.
  virtual bool GetRecentMedianDownlinkThroughputKbps(
      const base::TimeTicks& begin_timestamp,
      int32_t* kbps) const WARN_UNUSED_RESULT;

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
  void OnUpdatedEstimateAvailable() override;

  // Return a string equivalent to |type|.
  const char* GetNameForEffectiveConnectionType(
      EffectiveConnectionType type) const;

 private:
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, StoreObservations);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, TestAddObservation);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, ObtainOperatingParams);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, HalfLifeParam);
  FRIEND_TEST_ALL_PREFIXES(URLRequestTestHTTP, NetworkQualityEstimator);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest,
                           PercentileSameTimestamps);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest,
                           PercentileDifferentTimestamps);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, ComputedPercentiles);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, TestCaching);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest,
                           TestLRUCacheMaximumSize);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, TestGetMedianRTTSince);
  FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest,
                           TestExternalEstimateProviderMergeEstimates);

  class SocketWatcher;
  class SocketWatcherFactory;

  // NetworkQuality is used to cache the quality of a network connection.
  class NET_EXPORT_PRIVATE NetworkQuality {
   public:
    NetworkQuality();
    // |rtt| is the estimate of the round trip time.
    // |downstream_throughput_kbps| is the estimate of the downstream
    // throughput in kilobits per second.
    NetworkQuality(const base::TimeDelta& rtt,
                   int32_t downstream_throughput_kbps);
    NetworkQuality(const NetworkQuality& other);
    ~NetworkQuality();

    NetworkQuality& operator=(const NetworkQuality& other);

    // Returns the estimate of the round trip time.
    const base::TimeDelta& rtt() const { return rtt_; }

    // Returns the estimate of the downstream throughput in Kbps (Kilobits per
    // second).
    int32_t downstream_throughput_kbps() const {
      return downstream_throughput_kbps_;
    }

   private:
    // Estimated round trip time.
    base::TimeDelta rtt_;

    // Estimated downstream throughput in kilobits per second.
    int32_t downstream_throughput_kbps_;
  };

  // CachedNetworkQuality stores the quality of a previously seen network.
  class NET_EXPORT_PRIVATE CachedNetworkQuality {
   public:
    explicit CachedNetworkQuality(const NetworkQuality& network_quality);
    CachedNetworkQuality(const CachedNetworkQuality& other);
    ~CachedNetworkQuality();

    // Returns the network quality associated with this cached entry.
    const NetworkQuality& network_quality() const { return network_quality_; }

    // Returns true if this cache entry was updated before
    // |cached_network_quality|.
    bool OlderThan(const CachedNetworkQuality& cached_network_quality) const;

    // Time when this cache entry was last updated.
    const base::TimeTicks last_update_time_;

    // Quality of this cached network.
    const NetworkQuality network_quality_;

   private:
    DISALLOW_ASSIGN(CachedNetworkQuality);
  };

  // Records observations of network quality metrics (such as round trip time
  // or throughput), along with the time the observation was made. Observations
  // can be made at several places in the network stack, thus the observation
  // source is provided as well. ValueType must be numerical so that statistics
  // such as median, average can be computed.
  template <typename ValueType>
  struct NET_EXPORT_PRIVATE Observation {
    Observation(const ValueType& value,
                base::TimeTicks timestamp,
                ObservationSource source)
        : value(value), timestamp(timestamp), source(source) {
      DCHECK(!timestamp.is_null());
    }
    ~Observation() {}

    // Value of the observation.
    const ValueType value;

    // Time when the observation was taken.
    const base::TimeTicks timestamp;

    // The source of the observation.
    const ObservationSource source;
  };

  // Holds an observation and its weight.
  template <typename ValueType>
  struct NET_EXPORT_PRIVATE WeightedObservation {
    WeightedObservation(ValueType value, double weight)
        : value(value), weight(weight) {}
    WeightedObservation(const WeightedObservation& other)
        : WeightedObservation(other.value, other.weight) {}

    WeightedObservation& operator=(const WeightedObservation& other) {
      value = other.value;
      weight = other.weight;
      return *this;
    }

    // Required for sorting the samples in the ascending order of values.
    bool operator<(const WeightedObservation& other) const {
      return (value < other.value);
    }

    // Value of the sample.
    ValueType value;

    // Weight of the sample. This is computed based on how much time has passed
    // since the sample was taken.
    double weight;
  };

  // Stores observations sorted by time.
  template <typename ValueType>
  class NET_EXPORT_PRIVATE ObservationBuffer {
   public:
    explicit ObservationBuffer(double weight_multiplier_per_second);
    ~ObservationBuffer();

    // Adds |observation| to the buffer. The oldest observation in the buffer
    // will be evicted to make room if the buffer is already full.
    void AddObservation(const Observation<ValueType>& observation) {
      DCHECK_LE(observations_.size(),
                static_cast<size_t>(kMaximumObservationsBufferSize));
      // Evict the oldest element if the buffer is already full.
      if (observations_.size() == kMaximumObservationsBufferSize)
        observations_.pop_front();

      observations_.push_back(observation);
      DCHECK_LE(observations_.size(),
                static_cast<size_t>(kMaximumObservationsBufferSize));
    }

    // Clears the observations stored in this buffer.
    void Clear() { observations_.clear(); }

    // Returns true iff the |percentile| value of the observations in this
    // buffer is available. Sets |result| to the computed |percentile|
    // value among all observations since |begin_timestamp|. If the value is
    // unavailable, false is returned and |result| is not modified. Percentile
    // value is unavailable if all the values in observation buffer are older
    // than |begin_timestamp|. |result| must not be null.
    // |disallowed_observation_sources| is the list of observation sources that
    // should be excluded when computing the percentile.
    bool GetPercentile(
        const base::TimeTicks& begin_timestamp,
        ValueType* result,
        int percentile,
        const std::vector<ObservationSource>& disallowed_observation_sources)
        const WARN_UNUSED_RESULT;

   private:
    FRIEND_TEST_ALL_PREFIXES(NetworkQualityEstimatorTest, HalfLifeParam);

    // Computes the weighted observations and stores them in
    // |weighted_observations| sorted by ascending |WeightedObservation.value|.
    // Only the observations with timestamp later than |begin_timestamp| are
    // considered. Also, sets |total_weight| to the total weight of all
    // observations. Should be called only when there is at least one
    // observation in the buffer. |disallowed_observation_sources| is the list
    // of observation sources that should be excluded when computing the
    // weighted observations.
    void ComputeWeightedObservations(
        const base::TimeTicks& begin_timestamp,
        std::vector<WeightedObservation<ValueType>>& weighted_observations,
        double* total_weight,
        const std::vector<ObservationSource>& disallowed_observation_sources)
        const;

    // Holds observations sorted by time, with the oldest observation at the
    // front of the queue.
    std::deque<Observation<ValueType>> observations_;

    // The factor by which the weight of an observation reduces every second.
    // For example, if an observation is 6 seconds old, its weight would be:
    //     weight_multiplier_per_second_ ^ 6
    // Calculated from |kHalfLifeSeconds| by solving the following equation:
    //     weight_multiplier_per_second_ ^ kHalfLifeSeconds = 0.5
    const double weight_multiplier_per_second_;

    DISALLOW_COPY_AND_ASSIGN(ObservationBuffer);
  };

  // Value of round trip time observations is in base::TimeDelta.
  typedef net::NetworkQualityEstimator::Observation<base::TimeDelta>
      RttObservation;
  typedef net::NetworkQualityEstimator::ObservationBuffer<base::TimeDelta>
      RttObservationBuffer;

  // Value of throughput observations is in kilobits per second.
  typedef net::NetworkQualityEstimator::Observation<int32_t>
      ThroughputObservation;
  typedef net::NetworkQualityEstimator::ObservationBuffer<int32_t>
      ThroughputObservationBuffer;

  // This does not use a unordered_map or hash_map for code simplicity (key just
  // implements operator<, rather than hash and equality) and because the map is
  // tiny.
  typedef std::map<NetworkID, CachedNetworkQuality> CachedNetworkQualities;

  // Throughput is set to |kInvalidThroughput| if a valid value is
  // unavailable. Readers should discard throughput value if it is set to
  // |kInvalidThroughput|.
  static const int32_t kInvalidThroughput;

  // Tiny transfer sizes may give inaccurate throughput results.
  // Minimum size of the transfer over which the throughput is computed.
  static const int kMinTransferSizeInBytes = 10000;

  // Minimum duration (in microseconds) of the transfer over which the
  // throughput is computed.
  static const int kMinRequestDurationMicroseconds = 1000;

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

  // Maximum number of observations that can be held in the ObservationBuffer.
  static const size_t kMaximumObservationsBufferSize = 300;

  // Time duration (in milliseconds) after which the estimate provided by
  // external estimate provider is considered stale.
  static const int kExternalEstimateProviderFreshnessDurationMsec =
      5 * 60 * 1000;

  // Returns the RTT value to be used when the valid RTT is unavailable. Readers
  // should discard RTT if it is set to the value returned by |InvalidRTT()|.
  static const base::TimeDelta InvalidRTT();

  // Notifies |this| of a new transport layer RTT.
  void OnUpdatedRTTAvailable(SocketPerformanceWatcherFactory::Protocol protocol,
                             const base::TimeDelta& rtt);

  // Queries the external estimate provider for the latest network quality
  // estimates, and adds those estimates to the current observation buffer.
  void QueryExternalEstimateProvider();

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
  // Only the observations later than |begin_timestamp| are taken into account.
  // |percentile| must be between 0 and 100 (both inclusive) with higher
  // percentiles indicating less performant networks. For example, if
  // |percentile| is 90, then the network is expected to be faster than the
  // returned estimate with 0.9 probability. Similarly, network is expected to
  // be slower than the returned estimate with 0.1 probability.
  base::TimeDelta GetRTTEstimateInternal(
      const std::vector<ObservationSource>& disallowed_observation_sources,
      const base::TimeTicks& begin_timestamp,
      int percentile) const;
  int32_t GetDownlinkThroughputKbpsEstimateInternal(
      const base::TimeTicks& begin_timestamp,
      int percentile) const;

  // Returns the current network ID checking by calling the platform APIs.
  // Virtualized for testing.
  virtual NetworkID GetCurrentNetworkID() const;

  // Writes the estimated quality of the current network to the cache.
  void CacheNetworkQualityEstimate();

  void NotifyObserversOfRTT(const RttObservation& observation);

  void NotifyObserversOfThroughput(const ThroughputObservation& observation);

  // Records the UMA related to RTT.
  void RecordRTTUMA(int32_t estimated_value_msec,
                    int32_t actual_value_msec) const;

  // Returns true only if |request| can be used for network quality estimation.
  // Only the requests that go over network are considered to provide useful
  // observations.
  bool RequestProvidesUsefulObservations(const URLRequest& request) const;

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
  const bool allow_localhost_requests_;

  // Determines if the responses smaller than |kMinTransferSizeInBytes|
  // or shorter than |kMinTransferSizeInBytes| can be used in estimating the
  // network quality. Set to true only for tests.
  const bool allow_small_responses_;

  // The factor by which the weight of an observation reduces every second.
  const double weight_multiplier_per_second_;

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
  NetworkQuality peak_network_quality_;

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
  NetworkQuality
      default_observations_[NetworkChangeNotifier::CONNECTION_LAST + 1];

  // Thresholds for different effective connection types obtained from field
  // trial variation params. These thresholds encode how different connection
  // types behave in general. In future, complex encodings (e.g., curve
  // fitting) may be used.
  NetworkQuality connection_thresholds_[EFFECTIVE_CONNECTION_TYPE_LAST];

  // Estimated network quality. Updated on mainframe requests.
  NetworkQuality estimated_median_network_quality_;

  // ExternalEstimateProvider that provides network quality using operating
  // system APIs. May be NULL.
  const std::unique_ptr<ExternalEstimateProvider> external_estimate_provider_;

  // Observer lists for round trip times and throughput measurements.
  base::ObserverList<RTTObserver> rtt_observer_list_;
  base::ObserverList<ThroughputObserver> throughput_observer_list_;

  std::unique_ptr<SocketPerformanceWatcherFactory> watcher_factory_;

  base::ThreadChecker thread_checker_;

  base::WeakPtrFactory<NetworkQualityEstimator> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(NetworkQualityEstimator);
};

}  // namespace net

#endif  // NET_NQE_NETWORK_QUALITY_ESTIMATOR_H_

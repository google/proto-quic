// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_NETWORK_QUALITY_ESTIMATOR_TEST_UTIL_H_
#define NET_NQE_NETWORK_QUALITY_ESTIMATOR_TEST_UTIL_H_

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/files/file_path.h"
#include "base/macros.h"
#include "base/optional.h"
#include "base/time/time.h"
#include "net/base/network_change_notifier.h"
#include "net/log/net_log.h"
#include "net/log/test_net_log.h"
#include "net/nqe/effective_connection_type.h"
#include "net/nqe/network_quality_estimator.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

class ExternalEstimateProvider;

// Helps in setting the current network type and id.
class TestNetworkQualityEstimator : public NetworkQualityEstimator {
 public:
  TestNetworkQualityEstimator();

  explicit TestNetworkQualityEstimator(
      const std::map<std::string, std::string>& variation_params);

  TestNetworkQualityEstimator(
      const std::map<std::string, std::string>& variation_params,
      std::unique_ptr<net::ExternalEstimateProvider>
          external_estimate_provider);

  TestNetworkQualityEstimator(
      std::unique_ptr<net::ExternalEstimateProvider> external_estimate_provider,
      const std::map<std::string, std::string>& variation_params,
      bool allow_local_host_requests_for_tests,
      bool allow_smaller_responses_for_tests,
      bool add_default_platform_observations,
      std::unique_ptr<BoundTestNetLog> net_log);

  TestNetworkQualityEstimator(
      std::unique_ptr<net::ExternalEstimateProvider> external_estimate_provider,
      const std::map<std::string, std::string>& variation_params,
      bool allow_local_host_requests_for_tests,
      bool allow_smaller_responses_for_tests,
      bool add_default_platform_observations,
      bool suppress_notifications_for_testing,
      std::unique_ptr<BoundTestNetLog> net_log);

  ~TestNetworkQualityEstimator() override;

  // Runs one URL request to completion.
  void RunOneRequest();

  // Overrides the current network type and id.
  // Notifies network quality estimator of a change in connection.
  void SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType new_connection_type,
      const std::string& network_id);

  // Returns a GURL hosted at the embedded test server.
  const GURL GetEchoURL() const;

  // Returns a GURL hosted at the embedded test server which contains redirect
  // to another HTTPS URL.
  const GURL GetRedirectURL() const;

  void set_effective_connection_type(EffectiveConnectionType type) {
    // Callers should not set effective connection type along with the
    // lower-layer metrics.
    DCHECK(!start_time_null_http_rtt_ && !recent_http_rtt_ &&
           !start_time_null_transport_rtt_ && !recent_transport_rtt_ &&
           !start_time_null_downlink_throughput_kbps_ &&
           !recent_downlink_throughput_kbps_);
    effective_connection_type_ = type;
  }

  // Returns the effective connection type that was set using
  // |set_effective_connection_type|. If the connection type has not been set,
  // then the base implementation is called.
  EffectiveConnectionType GetEffectiveConnectionType() const override;

  void set_recent_effective_connection_type(EffectiveConnectionType type) {
    // Callers should not set effective connection type along with the
    // lower-layer metrics.
    DCHECK(!start_time_null_http_rtt_ && !recent_http_rtt_ &&
           !start_time_null_transport_rtt_ && !recent_transport_rtt_ &&
           !start_time_null_downlink_throughput_kbps_ &&
           !recent_downlink_throughput_kbps_);
    recent_effective_connection_type_ = type;
  }

  // Returns the effective connection type that was set using
  // |set_effective_connection_type|. If the connection type has not been set,
  // then the base implementation is called.
  EffectiveConnectionType GetRecentEffectiveConnectionType(
      const base::TimeTicks& start_time) const override;

  // Returns the effective connection type that was set using
  // |set_effective_connection_type|. If the connection type has not been set,
  // then the base implementation is called. |http_rtt|, |transport_rtt| and
  // |downstream_throughput_kbps| are set to the values that were previously
  // set by calling set_recent_http_rtt(), set_recent_transport_rtt()
  // and set_recent_transport_rtt() methods, respectively.
  EffectiveConnectionType GetRecentEffectiveConnectionTypeAndNetworkQuality(
      const base::TimeTicks& start_time,
      base::TimeDelta* http_rtt,
      base::TimeDelta* transport_rtt,
      int32_t* downstream_throughput_kbps) const override;

  void NotifyObserversOfRTTOrThroughputComputed() const override;

  void NotifyRTTAndThroughputEstimatesObserverIfPresent(
      RTTAndThroughputEstimatesObserver* observer) const override;

  void set_start_time_null_http_rtt(const base::TimeDelta& http_rtt) {
    // Callers should not set effective connection type along with the
    // lower-layer metrics.
    DCHECK(!effective_connection_type_ && !recent_effective_connection_type_);
    start_time_null_http_rtt_ = http_rtt;
  }

  void set_recent_http_rtt(const base::TimeDelta& recent_http_rtt) {
    // Callers should not set effective connection type along with the
    // lower-layer metrics.
    DCHECK(!effective_connection_type_ && !recent_effective_connection_type_);
    recent_http_rtt_ = recent_http_rtt;
  }
  // Returns the recent HTTP RTT that was set using |set_recent_http_rtt|. If
  // the recent HTTP RTT has not been set, then the base implementation is
  // called.
  bool GetRecentHttpRTT(const base::TimeTicks& start_time,
                        base::TimeDelta* rtt) const override;

  void set_start_time_null_transport_rtt(const base::TimeDelta& transport_rtt) {
    // Callers should not set effective connection type along with the
    // lower-layer metrics.
    DCHECK(!effective_connection_type_ && !recent_effective_connection_type_);
    start_time_null_transport_rtt_ = transport_rtt;
  }

  void set_recent_transport_rtt(const base::TimeDelta& recent_transport_rtt) {
    // Callers should not set effective connection type along with the
    // lower-layer metrics.
    DCHECK(!effective_connection_type_ && !recent_effective_connection_type_);
    recent_transport_rtt_ = recent_transport_rtt;
  }

  base::Optional<base::TimeDelta> GetTransportRTT() const override;

  // Returns the recent transport RTT that was set using
  // |set_recent_transport_rtt|. If the recent transport RTT has not been set,
  // then the base implementation is called.
  bool GetRecentTransportRTT(const base::TimeTicks& start_time,
                             base::TimeDelta* rtt) const override;

  void set_start_time_null_downlink_throughput_kbps(
      int32_t downlink_throughput_kbps) {
    // Callers should not set effective connection type along with the
    // lower-layer metrics.
    DCHECK(!effective_connection_type_ && !recent_effective_connection_type_);
    start_time_null_downlink_throughput_kbps_ = downlink_throughput_kbps;
  }

  void set_recent_downlink_throughput_kbps(
      int32_t recent_downlink_throughput_kbps) {
    // Callers should not set effective connection type along with the
    // lower-layer metrics.
    DCHECK(!effective_connection_type_ && !recent_effective_connection_type_);
    recent_downlink_throughput_kbps_ = recent_downlink_throughput_kbps;
  }
  // Returns the downlink throughput that was set using
  // |set_recent_downlink_throughput_kbps|. If the downlink throughput has not
  // been set, then the base implementation is called.
  bool GetRecentDownlinkThroughputKbps(const base::TimeTicks& start_time,
                                       int32_t* kbps) const override;

  // Returns the recent HTTP RTT value that was set using
  // |set_rtt_estimate_internal|. If it has not been set, then the base
  // implementation is called.
  base::TimeDelta GetRTTEstimateInternal(
      const std::vector<NetworkQualityObservationSource>&
          disallowed_observation_sources,
      base::TimeTicks start_time,
      const base::Optional<NetworkQualityEstimator::Statistic>& statistic,
      int percentile) const override;

  void set_rtt_estimate_internal(base::TimeDelta value) {
    rtt_estimate_internal_ = value;
  }

  void SetAccuracyRecordingIntervals(
      const std::vector<base::TimeDelta>& accuracy_recording_intervals);

  const std::vector<base::TimeDelta>& GetAccuracyRecordingIntervals()
      const override;

  void set_rand_double(double rand_double) { rand_double_ = rand_double; }

  double RandDouble() const override;

  // Returns the number of entries in |net_log_| that have type set to |type|.
  int GetEntriesCount(NetLogEventType type) const;

  // Returns the value of the parameter with name |key| from the last net log
  // entry that has type set to |type|. Different methods are provided for
  // values of different types.
  std::string GetNetLogLastStringValue(NetLogEventType type,
                                       const std::string& key) const;
  int GetNetLogLastIntegerValue(NetLogEventType type,
                                const std::string& key) const;

  // Notifies the registered observers that the network quality estimate has
  // changed to |network_quality|.
  void NotifyObserversOfRTTOrThroughputEstimatesComputed(
      const net::nqe::internal::NetworkQuality& network_quality);

  // Notifies the registered observers that the network quality estimate has
  // changed to |network_quality|.
  void NotifyObserversOfEffectiveConnectionType(EffectiveConnectionType type);

  using NetworkQualityEstimator::SetTickClockForTesting;
  using NetworkQualityEstimator::OnConnectionTypeChanged;
  using NetworkQualityEstimator::OnUpdatedRTTAvailable;

 private:
  class LocalHttpTestServer : public EmbeddedTestServer {
   public:
    explicit LocalHttpTestServer(const base::FilePath& document_root);
  };

  // NetworkQualityEstimator implementation that returns the overridden
  // network
  // id (instead of invoking platform APIs).
  nqe::internal::NetworkID GetCurrentNetworkID() const override;

  // If set, GetEffectiveConnectionType() and GetRecentEffectiveConnectionType()
  // would return the set values, respectively.
  base::Optional<EffectiveConnectionType> effective_connection_type_;
  base::Optional<EffectiveConnectionType> recent_effective_connection_type_;

  NetworkChangeNotifier::ConnectionType current_network_type_;
  std::string current_network_id_;

  bool accuracy_recording_intervals_set_;
  std::vector<base::TimeDelta> accuracy_recording_intervals_;

  // If set, GetRecentHttpRTT() would return one of the set values.
  // |start_time_null_http_rtt_| is returned if the |start_time| is null.
  // Otherwise, |recent_http_rtt_| is returned.
  base::Optional<base::TimeDelta> start_time_null_http_rtt_;
  base::Optional<base::TimeDelta> recent_http_rtt_;

  // If set, GetRecentTransportRTT() would return one of the set values.
  // |start_time_null_transport_rtt_| is returned if the |start_time| is null.
  // Otherwise, |recent_transport_rtt_| is returned.
  base::Optional<base::TimeDelta> start_time_null_transport_rtt_;
  base::Optional<base::TimeDelta> recent_transport_rtt_;

  // If set, GetRecentDownlinkThroughputKbps() would return one of the set
  // values. |start_time_null_downlink_throughput_kbps_| is returned if the
  // |start_time| is null. Otherwise, |recent_downlink_throughput_kbps_| is
  // returned.
  base::Optional<int32_t> start_time_null_downlink_throughput_kbps_;
  base::Optional<int32_t> recent_downlink_throughput_kbps_;

  // If set, GetRTTEstimateInternal() would return the set value.
  base::Optional<base::TimeDelta> rtt_estimate_internal_;

  double rand_double_;

  LocalHttpTestServer embedded_test_server_;

  // If true, notifications are not sent to any of the observers.
  const bool suppress_notifications_for_testing_;

  // Net log provided to network quality estimator.
  std::unique_ptr<net::BoundTestNetLog> net_log_;

  DISALLOW_COPY_AND_ASSIGN(TestNetworkQualityEstimator);
};

}  // namespace net

#endif  // NET_NQE_NETWORK_QUALITY_ESTIMATOR_TEST_UTIL_H_

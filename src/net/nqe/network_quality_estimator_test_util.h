// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/network_quality_estimator.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "base/macros.h"
#include "base/time/time.h"
#include "net/base/network_change_notifier.h"
#include "net/nqe/effective_connection_type.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

class ExternalEstimateProvider;

namespace test_server {
struct HttpRequest;
class HttpResponse;
}

// Helps in setting the current network type and id.
class TestNetworkQualityEstimator : public NetworkQualityEstimator {
 public:
  TestNetworkQualityEstimator(
      const std::map<std::string, std::string>& variation_params,
      std::unique_ptr<net::ExternalEstimateProvider>
          external_estimate_provider);

  TestNetworkQualityEstimator(
      std::unique_ptr<net::ExternalEstimateProvider> external_estimate_provider,
      const std::map<std::string, std::string>& variation_params,
      bool allow_local_host_requests_for_tests,
      bool allow_smaller_responses_for_tests);

  explicit TestNetworkQualityEstimator(
      const std::map<std::string, std::string>& variation_params);

  ~TestNetworkQualityEstimator() override;

  // Runs one URL request to completion.
  void RunOneRequest();

  // Overrides the current network type and id.
  // Notifies network quality estimator of a change in connection.
  void SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType new_connection_type,
      const std::string& network_id);

  // Called by the embedded server when an HTTP request is received.
  std::unique_ptr<test_server::HttpResponse> HandleRequest(
      const test_server::HttpRequest& request);

  // Returns a GURL hosted at the embedded test server.
  const GURL GetEchoURL() const;

  void set_effective_connection_type(EffectiveConnectionType type) {
    effective_connection_type_set_ = true;
    effective_connection_type_ = type;
  }

  // Returns the effective connection type that was set using
  // |set_effective_connection_type|. If the connection type has not been set,
  // then the base implementation is called.
  EffectiveConnectionType GetEffectiveConnectionType() const override;

  void set_recent_effective_connection_type(EffectiveConnectionType type) {
    recent_effective_connection_type_set_ = true;
    recent_effective_connection_type_ = type;
  }

  // Returns the effective connection type that was set using
  // |set_effective_connection_type|. If the connection type has not been set,
  // then the base implementation is called.
  EffectiveConnectionType GetRecentEffectiveConnectionType(
      const base::TimeTicks& start_time) const override;

  void set_http_rtt(const base::TimeDelta& http_rtt) {
    http_rtt_set_ = true;
    http_rtt_ = http_rtt;
  }
  // Returns the HTTP RTT that was set using |set_http_rtt|. If the HTTP RTT has
  // not been set, then the base implementation is called.
  bool GetHttpRTT(base::TimeDelta* rtt) const override;

  void set_recent_http_rtt(const base::TimeDelta& recent_http_rtt) {
    recent_http_rtt_set_ = true;
    recent_http_rtt_ = recent_http_rtt;
  }
  // Returns the recent HTTP RTT that was set using |set_recent_http_rtt|. If
  // the recent HTTP RTT has not been set, then the base implementation is
  // called.
  bool GetRecentHttpRTT(const base::TimeTicks& start_time,
                        base::TimeDelta* rtt) const override;

  void set_transport_rtt(const base::TimeDelta& transport_rtt) {
    transport_rtt_set_ = true;
    transport_rtt_ = transport_rtt;
  }
  // Returns the transport RTT that was set using |set_transport_rtt|. If the
  // transport RTT has not been set, then the base implementation is called.
  bool GetTransportRTT(base::TimeDelta* rtt) const override;

  void set_recent_transport_rtt(const base::TimeDelta& recent_transport_rtt) {
    recent_transport_rtt_set_ = true;
    recent_transport_rtt_ = recent_transport_rtt;
  }
  // Returns the recent transport RTT that was set using
  // |set_recent_transport_rtt|. If the recent transport RTT has not been set,
  // then the base implementation is called.
  bool GetRecentTransportRTT(const base::TimeTicks& start_time,
                             base::TimeDelta* rtt) const override;

  void set_downlink_throughput_kbps(int32_t downlink_throughput_kbps) {
    downlink_throughput_kbps_set_ = true;
    downlink_throughput_kbps_ = downlink_throughput_kbps;
  }
  // Returns the downlink throughput that was set using
  // |set_downlink_throughput_kbps|. If the downlink throughput has not been
  // set, then the base implementation is called.
  bool GetDownlinkThroughputKbps(int32_t* kbps) const override;

  void set_recent_downlink_throughput_kbps(
      int32_t recent_downlink_throughput_kbps) {
    recent_downlink_throughput_kbps_set_ = true;
    recent_downlink_throughput_kbps_ = recent_downlink_throughput_kbps;
  }
  // Returns the downlink throughput that was set using
  // |set_recent_downlink_throughput_kbps|. If the downlink throughput has not
  // been set, then the base implementation is called.
  bool GetRecentDownlinkThroughputKbps(const base::TimeTicks& start_time,
                                       int32_t* kbps) const override;

  void SetAccuracyRecordingIntervals(
      const std::vector<base::TimeDelta>& accuracy_recording_intervals);

  const std::vector<base::TimeDelta>& GetAccuracyRecordingIntervals()
      const override;

  void set_rand_double(double rand_double) { rand_double_ = rand_double; }

  double RandDouble() const override;

  using NetworkQualityEstimator::SetTickClockForTesting;
  using NetworkQualityEstimator::OnConnectionTypeChanged;

 private:
  // NetworkQualityEstimator implementation that returns the overridden
  // network
  // id (instead of invoking platform APIs).
  nqe::internal::NetworkID GetCurrentNetworkID() const override;

  bool effective_connection_type_set_;
  EffectiveConnectionType effective_connection_type_;

  bool recent_effective_connection_type_set_;
  EffectiveConnectionType recent_effective_connection_type_;

  NetworkChangeNotifier::ConnectionType current_network_type_;
  std::string current_network_id_;

  bool accuracy_recording_intervals_set_;
  std::vector<base::TimeDelta> accuracy_recording_intervals_;

  bool http_rtt_set_;
  base::TimeDelta http_rtt_;

  bool recent_http_rtt_set_;
  base::TimeDelta recent_http_rtt_;

  bool transport_rtt_set_;
  base::TimeDelta transport_rtt_;

  bool recent_transport_rtt_set_;
  base::TimeDelta recent_transport_rtt_;

  bool downlink_throughput_kbps_set_;
  int32_t downlink_throughput_kbps_;

  bool recent_downlink_throughput_kbps_set_;
  int32_t recent_downlink_throughput_kbps_;

  double rand_double_;

  EmbeddedTestServer embedded_test_server_;

  DISALLOW_COPY_AND_ASSIGN(TestNetworkQualityEstimator);
};

}  // namespace net

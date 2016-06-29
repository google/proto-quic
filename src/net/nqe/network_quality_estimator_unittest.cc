// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/network_quality_estimator.h"

#include <stddef.h>
#include <stdint.h>

#include <limits>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/files/file_path.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/metrics/histogram_samples.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/histogram_tester.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/load_flags.h"
#include "net/base/network_change_notifier.h"
#include "net/http/http_status_code.h"
#include "net/nqe/external_estimate_provider.h"
#include "net/nqe/network_quality_observation.h"
#include "net/nqe/network_quality_observation_source.h"
#include "net/nqe/observation_buffer.h"
#include "net/socket/socket_performance_watcher.h"
#include "net/socket/socket_performance_watcher_factory.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/embedded_test_server/http_request.h"
#include "net/test/embedded_test_server/http_response.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

namespace {

// Helps in setting the current network type and id.
class TestNetworkQualityEstimator : public NetworkQualityEstimator {
 public:
  TestNetworkQualityEstimator(
      const std::map<std::string, std::string>& variation_params,
      std::unique_ptr<net::ExternalEstimateProvider> external_estimate_provider)
      : TestNetworkQualityEstimator(std::move(external_estimate_provider),
                                    variation_params,
                                    true,
                                    true) {}

  TestNetworkQualityEstimator(
      std::unique_ptr<net::ExternalEstimateProvider> external_estimate_provider,
      const std::map<std::string, std::string>& variation_params,
      bool allow_local_host_requests_for_tests,
      bool allow_smaller_responses_for_tests)
      : NetworkQualityEstimator(std::move(external_estimate_provider),
                                variation_params,
                                allow_local_host_requests_for_tests,
                                allow_smaller_responses_for_tests),
        effective_connection_type_set_(false),
        effective_connection_type_(EFFECTIVE_CONNECTION_TYPE_UNKNOWN),
        recent_effective_connection_type_set_(false),
        recent_effective_connection_type_(EFFECTIVE_CONNECTION_TYPE_UNKNOWN),
        current_network_type_(NetworkChangeNotifier::CONNECTION_UNKNOWN),
        accuracy_recording_intervals_set_(false),
        http_rtt_set_(false),
        recent_http_rtt_set_(false),
        transport_rtt_set_(false),
        recent_transport_rtt_set_(false),
        downlink_throughput_kbps_set_(false),
        recent_downlink_throughput_kbps_set_(false) {
    // Set up embedded test server.
    embedded_test_server_.ServeFilesFromDirectory(
        base::FilePath(FILE_PATH_LITERAL("net/data/url_request_unittest")));
    EXPECT_TRUE(embedded_test_server_.Start());
    embedded_test_server_.RegisterRequestHandler(base::Bind(
        &TestNetworkQualityEstimator::HandleRequest, base::Unretained(this)));
  }

  explicit TestNetworkQualityEstimator(
      const std::map<std::string, std::string>& variation_params)
      : TestNetworkQualityEstimator(
            variation_params,
            std::unique_ptr<ExternalEstimateProvider>()) {}

  ~TestNetworkQualityEstimator() override {}

  // Overrides the current network type and id.
  // Notifies network quality estimator of change in connection.
  void SimulateNetworkChangeTo(NetworkChangeNotifier::ConnectionType type,
                               const std::string& network_id) {
    current_network_type_ = type;
    current_network_id_ = network_id;
    OnConnectionTypeChanged(type);
  }

  // Called by embedded server when a HTTP request is received.
  std::unique_ptr<test_server::HttpResponse> HandleRequest(
      const test_server::HttpRequest& request) {
    std::unique_ptr<test_server::BasicHttpResponse> http_response(
        new test_server::BasicHttpResponse());
    http_response->set_code(HTTP_OK);
    http_response->set_content("hello");
    http_response->set_content_type("text/plain");
    return std::move(http_response);
  }

  // Returns a GURL hosted at embedded test server.
  const GURL GetEchoURL() const {
    return embedded_test_server_.GetURL("/echo.html");
  }

  void set_effective_connection_type(EffectiveConnectionType type) {
    effective_connection_type_set_ = true;
    effective_connection_type_ = type;
  }

  // Returns the effective connection type that was set using
  // |set_effective_connection_type|. If connection type has not been set, then
  // the base implementation is called.
  EffectiveConnectionType GetEffectiveConnectionType() const override {
    if (effective_connection_type_set_)
      return effective_connection_type_;
    return NetworkQualityEstimator::GetEffectiveConnectionType();
  }

  void set_recent_effective_connection_type(EffectiveConnectionType type) {
    recent_effective_connection_type_set_ = true;
    recent_effective_connection_type_ = type;
  }

  // Returns the effective connection type that was set using
  // |set_effective_connection_type|. If connection type has not been set, then
  // the base implementation is called.
  EffectiveConnectionType GetRecentEffectiveConnectionType(
      const base::TimeTicks& start_time) const override {
    if (recent_effective_connection_type_set_)
      return recent_effective_connection_type_;
    return NetworkQualityEstimator::GetRecentEffectiveConnectionType(
        start_time);
  }

  void set_http_rtt(const base::TimeDelta& http_rtt) {
    http_rtt_set_ = true;
    http_rtt_ = http_rtt;
  }

  // Returns the HTTP RTT that was set using |set_http_rtt|. If the HTTP RTT has
  // not been set, then the base implementation is called.
  bool GetHttpRTTEstimate(base::TimeDelta* rtt) const override {
    if (http_rtt_set_) {
      *rtt = http_rtt_;
      return true;
    }
    return NetworkQualityEstimator::GetHttpRTTEstimate(rtt);
  }

  void set_recent_http_rtt(const base::TimeDelta& recent_http_rtt) {
    recent_http_rtt_set_ = true;
    recent_http_rtt_ = recent_http_rtt;
  }

  // Returns the recent HTTP RTT that was set using |set_recent_http_rtt|. If
  // the recent HTTP RTT has not been set, then the base implementation is
  // called.
  bool GetRecentHttpRTTMedian(const base::TimeTicks& start_time,
                              base::TimeDelta* rtt) const override {
    if (recent_http_rtt_set_) {
      *rtt = recent_http_rtt_;
      return true;
    }
    return NetworkQualityEstimator::GetRecentHttpRTTMedian(start_time, rtt);
  }

  void set_transport_rtt(const base::TimeDelta& transport_rtt) {
    transport_rtt_set_ = true;
    transport_rtt_ = transport_rtt;
  }

  // Returns the transport RTT that was set using |set_transport_rtt|. If the
  // transport RTT has not been set, then the base implementation is called.
  bool GetTransportRTTEstimate(base::TimeDelta* rtt) const override {
    if (transport_rtt_set_) {
      *rtt = transport_rtt_;
      return true;
    }
    return NetworkQualityEstimator::GetTransportRTTEstimate(rtt);
  }

  void set_recent_transport_rtt(const base::TimeDelta& recent_transport_rtt) {
    recent_transport_rtt_set_ = true;
    recent_transport_rtt_ = recent_transport_rtt;
  }

  // Returns the recent transport RTT that was set using
  // |set_recent_transport_rtt|. If the recent transport RTT has not been set,
  // then the base implementation is called.
  bool GetRecentTransportRTTMedian(const base::TimeTicks& start_time,
                                   base::TimeDelta* rtt) const override {
    if (recent_transport_rtt_set_) {
      *rtt = recent_transport_rtt_;
      return true;
    }
    return NetworkQualityEstimator::GetRecentTransportRTTMedian(start_time,
                                                                rtt);
  }

  void set_downlink_throughput_kbps(int32_t downlink_throughput_kbps) {
    downlink_throughput_kbps_set_ = true;
    downlink_throughput_kbps_ = downlink_throughput_kbps;
  }

  // Returns the downlink throughput that was set using
  // |set_downlink_throughput_kbps|. If the downlink throughput has not been
  // set, then the base implementation is called.
  bool GetDownlinkThroughputKbpsEstimate(int32_t* kbps) const override {
    if (downlink_throughput_kbps_set_) {
      *kbps = downlink_throughput_kbps_;
      return true;
    }
    return NetworkQualityEstimator::GetDownlinkThroughputKbpsEstimate(kbps);
  }

  void set_recent_downlink_throughput_kbps(
      int32_t recent_downlink_throughput_kbps) {
    recent_downlink_throughput_kbps_set_ = true;
    recent_downlink_throughput_kbps_ = recent_downlink_throughput_kbps;
  }

  // Returns the downlink throughput that was set using
  // |set_recent_downlink_throughput_kbps|. If the downlink throughput has not
  // been set, then the base implementation is called.
  bool GetRecentMedianDownlinkThroughputKbps(const base::TimeTicks& start_time,
                                             int32_t* kbps) const override {
    if (recent_downlink_throughput_kbps_set_) {
      *kbps = recent_downlink_throughput_kbps_;
      return true;
    }
    return NetworkQualityEstimator::GetRecentMedianDownlinkThroughputKbps(
        start_time, kbps);
  }

  void SetAccuracyRecordingIntervals(
      const std::vector<base::TimeDelta>& accuracy_recording_intervals) {
    accuracy_recording_intervals_set_ = true;
    accuracy_recording_intervals_ = accuracy_recording_intervals;
  }

  const std::vector<base::TimeDelta>& GetAccuracyRecordingIntervals()
      const override {
    if (accuracy_recording_intervals_set_)
      return accuracy_recording_intervals_;

    return NetworkQualityEstimator::GetAccuracyRecordingIntervals();
  }

  using NetworkQualityEstimator::SetTickClockForTesting;
  using NetworkQualityEstimator::ReadCachedNetworkQualityEstimate;
  using NetworkQualityEstimator::OnConnectionTypeChanged;

 private:
  // NetworkQualityEstimator implementation that returns the overridden
  // network
  // id (instead of invoking platform APIs).
  NetworkQualityEstimator::NetworkID GetCurrentNetworkID() const override {
    return NetworkQualityEstimator::NetworkID(current_network_type_,
                                              current_network_id_);
  }

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

  // Embedded server used for testing.
  EmbeddedTestServer embedded_test_server_;

  DISALLOW_COPY_AND_ASSIGN(TestNetworkQualityEstimator);
};

class TestEffectiveConnectionTypeObserver
    : public NetworkQualityEstimator::EffectiveConnectionTypeObserver {
 public:
  std::vector<NetworkQualityEstimator::EffectiveConnectionType>&
  effective_connection_types() {
    return effective_connection_types_;
  }

  // EffectiveConnectionTypeObserver implementation:
  void OnEffectiveConnectionTypeChanged(
      NetworkQualityEstimator::EffectiveConnectionType type) override {
    effective_connection_types_.push_back(type);
  }

 private:
  std::vector<NetworkQualityEstimator::EffectiveConnectionType>
      effective_connection_types_;
};

class TestRTTObserver : public NetworkQualityEstimator::RTTObserver {
 public:
  struct Observation {
    Observation(int32_t ms,
                const base::TimeTicks& ts,
                NetworkQualityObservationSource src)
        : rtt_ms(ms), timestamp(ts), source(src) {}
    int32_t rtt_ms;
    base::TimeTicks timestamp;
    NetworkQualityObservationSource source;
  };

  std::vector<Observation>& observations() { return observations_; }

  // RttObserver implementation:
  void OnRTTObservation(int32_t rtt_ms,
                        const base::TimeTicks& timestamp,
                        NetworkQualityObservationSource source) override {
    observations_.push_back(Observation(rtt_ms, timestamp, source));
  }

 private:
  std::vector<Observation> observations_;
};

class TestThroughputObserver
    : public NetworkQualityEstimator::ThroughputObserver {
 public:
  struct Observation {
    Observation(int32_t kbps,
                const base::TimeTicks& ts,
                NetworkQualityObservationSource src)
        : throughput_kbps(kbps), timestamp(ts), source(src) {}
    int32_t throughput_kbps;
    base::TimeTicks timestamp;
    NetworkQualityObservationSource source;
  };

  std::vector<Observation>& observations() { return observations_; }

  // ThroughputObserver implementation:
  void OnThroughputObservation(
      int32_t throughput_kbps,
      const base::TimeTicks& timestamp,
      NetworkQualityObservationSource source) override {
    observations_.push_back(Observation(throughput_kbps, timestamp, source));
  }

 private:
  std::vector<Observation> observations_;
};

}  // namespace

TEST(NetworkQualityEstimatorTest, TestKbpsRTTUpdates) {
  base::HistogramTester histogram_tester;
  // Enable requests to local host to be used for network quality estimation.
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);

  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_FALSE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));

  TestDelegate test_delegate;
  TestURLRequestContext context(true);
  context.set_network_quality_estimator(&estimator);
  context.Init();

  std::unique_ptr<URLRequest> request(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME);
  request->Start();
  base::RunLoop().Run();

  // Both RTT and downstream throughput should be updated.
  EXPECT_TRUE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  EXPECT_FALSE(estimator.GetTransportRTTEstimate(&rtt));

  // Check UMA histograms.
  histogram_tester.ExpectTotalCount("NQE.PeakKbps.Unknown", 0);
  histogram_tester.ExpectTotalCount("NQE.FastestRTT.Unknown", 0);
  histogram_tester.ExpectUniqueSample(
      "NQE.MainFrame.EffectiveConnectionType.Unknown",
      NetworkQualityEstimator::EffectiveConnectionType::
          EFFECTIVE_CONNECTION_TYPE_UNKNOWN,
      1);

  std::unique_ptr<URLRequest> request2(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request2->SetLoadFlags(request2->load_flags() | LOAD_MAIN_FRAME);
  request2->Start();
  base::RunLoop().Run();
  histogram_tester.ExpectTotalCount(
      "NQE.MainFrame.EffectiveConnectionType.Unknown", 2);

  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-1");
  histogram_tester.ExpectTotalCount("NQE.PeakKbps.Unknown", 1);
  histogram_tester.ExpectTotalCount("NQE.FastestRTT.Unknown", 1);

  histogram_tester.ExpectTotalCount("NQE.RatioMedianRTT.WiFi", 0);

  histogram_tester.ExpectTotalCount("NQE.RTT.Percentile0.Unknown", 1);
  histogram_tester.ExpectTotalCount("NQE.RTT.Percentile10.Unknown", 1);
  histogram_tester.ExpectTotalCount("NQE.RTT.Percentile50.Unknown", 1);
  histogram_tester.ExpectTotalCount("NQE.RTT.Percentile90.Unknown", 1);
  histogram_tester.ExpectTotalCount("NQE.RTT.Percentile100.Unknown", 1);

  histogram_tester.ExpectTotalCount("NQE.TransportRTT.Percentile50.Unknown", 0);

  EXPECT_FALSE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));

  // Verify that metrics are logged correctly on main-frame requests.
  histogram_tester.ExpectTotalCount("NQE.MainFrame.RTT.Percentile50.Unknown",
                                    1);
  histogram_tester.ExpectTotalCount(
      "NQE.MainFrame.TransportRTT.Percentile50.Unknown", 0);
  histogram_tester.ExpectTotalCount("NQE.MainFrame.Kbps.Percentile50.Unknown",
                                    1);

  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, std::string());
  histogram_tester.ExpectTotalCount("NQE.PeakKbps.Unknown", 1);
  histogram_tester.ExpectTotalCount("NQE.FastestRTT.Unknown", 1);

  EXPECT_FALSE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));

  std::unique_ptr<URLRequest> request3(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request3->SetLoadFlags(request2->load_flags() | LOAD_MAIN_FRAME);
  request3->Start();
  base::RunLoop().Run();
  histogram_tester.ExpectUniqueSample(
      "NQE.MainFrame.EffectiveConnectionType.WiFi",
      NetworkQualityEstimator::EffectiveConnectionType::
          EFFECTIVE_CONNECTION_TYPE_UNKNOWN,
      1);
}

TEST(NetworkQualityEstimatorTest, StoreObservations) {
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);

  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_FALSE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));

  TestDelegate test_delegate;
  TestURLRequestContext context(true);
  context.set_network_quality_estimator(&estimator);
  context.Init();

  // Push more observations than the maximum buffer size.
  const size_t kMaxObservations = 1000;
  for (size_t i = 0; i < kMaxObservations; ++i) {
    std::unique_ptr<URLRequest> request(context.CreateRequest(
        estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
    request->Start();
    base::RunLoop().Run();
    EXPECT_TRUE(estimator.GetHttpRTTEstimate(&rtt));
    EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  }

  // Verify that the stored observations are cleared on network change.
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-2");
  EXPECT_FALSE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
}

// This test notifies NetworkQualityEstimator of received data. Next,
// throughput and RTT percentiles are checked for correctness by doing simple
// verifications.
TEST(NetworkQualityEstimatorTest, ComputedPercentiles) {
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);

  std::vector<NetworkQualityObservationSource> disallowed_observation_sources;
  disallowed_observation_sources.push_back(
      NETWORK_QUALITY_OBSERVATION_SOURCE_TCP);
  disallowed_observation_sources.push_back(
      NETWORK_QUALITY_OBSERVATION_SOURCE_QUIC);

  EXPECT_EQ(nqe::internal::InvalidRTT(),
            estimator.GetRTTEstimateInternal(disallowed_observation_sources,
                                             base::TimeTicks(), 100));
  EXPECT_EQ(nqe::internal::kInvalidThroughput,
            estimator.GetDownlinkThroughputKbpsEstimateInternal(
                base::TimeTicks(), 100));

  TestDelegate test_delegate;
  TestURLRequestContext context(true);
  context.set_network_quality_estimator(&estimator);
  context.Init();

  // Number of observations are more than the maximum buffer size.
  for (size_t i = 0; i < 1000U; ++i) {
    std::unique_ptr<URLRequest> request(context.CreateRequest(
        estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
    request->Start();
    base::RunLoop().Run();
  }

  // Verify the percentiles through simple tests.
  for (int i = 0; i <= 100; ++i) {
    EXPECT_GT(estimator.GetDownlinkThroughputKbpsEstimateInternal(
                  base::TimeTicks(), i),
              0);
    EXPECT_LT(estimator.GetRTTEstimateInternal(disallowed_observation_sources,
                                               base::TimeTicks(), i),
              base::TimeDelta::Max());

    if (i != 0) {
      // Throughput percentiles are in decreasing order.
      EXPECT_LE(estimator.GetDownlinkThroughputKbpsEstimateInternal(
                    base::TimeTicks(), i),
                estimator.GetDownlinkThroughputKbpsEstimateInternal(
                    base::TimeTicks(), i - 1));

      // RTT percentiles are in increasing order.
      EXPECT_GE(estimator.GetRTTEstimateInternal(disallowed_observation_sources,
                                                 base::TimeTicks(), i),
                estimator.GetRTTEstimateInternal(disallowed_observation_sources,
                                                 base::TimeTicks(), i - 1));
    }
  }
}

TEST(NetworkQualityEstimatorTest, ObtainOperatingParams) {
  std::map<std::string, std::string> variation_params;
  variation_params["Unknown.DefaultMedianKbps"] = "100";
  variation_params["WiFi.DefaultMedianKbps"] = "200";
  variation_params["2G.DefaultMedianKbps"] = "300";

  variation_params["Unknown.DefaultMedianRTTMsec"] = "1000";
  variation_params["WiFi.DefaultMedianRTTMsec"] = "2000";
  // Negative variation value should not be used.
  variation_params["2G.DefaultMedianRTTMsec"] = "-5";

  TestNetworkQualityEstimator estimator(variation_params);

  base::TimeDelta rtt;
  EXPECT_TRUE(estimator.GetHttpRTTEstimate(&rtt));
  int32_t kbps;
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));

  EXPECT_EQ(100, kbps);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(1000), rtt);

  EXPECT_FALSE(estimator.GetTransportRTTEstimate(&rtt));

  // Simulate network change to Wi-Fi.
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-1");

  EXPECT_TRUE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  EXPECT_EQ(200, kbps);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(2000), rtt);
  EXPECT_FALSE(estimator.GetTransportRTTEstimate(&rtt));

  // Peak network quality should not be affected by the network quality
  // estimator field trial.
  EXPECT_EQ(nqe::internal::InvalidRTT(),
            estimator.peak_network_quality_.http_rtt());
  EXPECT_EQ(nqe::internal::kInvalidThroughput,
            estimator.peak_network_quality_.downstream_throughput_kbps());

  // Simulate network change to 2G. Only the Kbps default estimate should be
  // available.
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test-2");

  EXPECT_FALSE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  EXPECT_EQ(300, kbps);

  // Simulate network change to 3G. Default estimates should be unavailable.
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_3G, "test-3");

  EXPECT_FALSE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
}

TEST(NetworkQualityEstimatorTest, ObtainAlgorithmToUseFromParams) {
  const struct {
    bool set_variation_param;
    std::string algorithm;
    NetworkQualityEstimator::EffectiveConnectionTypeAlgorithm
        expected_algorithm;
  } tests[] = {
      {false, "", NetworkQualityEstimator::EffectiveConnectionTypeAlgorithm::
                      HTTP_RTT_AND_DOWNSTREAM_THROUGHOUT},
      {true, "", NetworkQualityEstimator::EffectiveConnectionTypeAlgorithm::
                     HTTP_RTT_AND_DOWNSTREAM_THROUGHOUT},
      {true, "HttpRTTAndDownstreamThroughput",
       NetworkQualityEstimator::EffectiveConnectionTypeAlgorithm::
           HTTP_RTT_AND_DOWNSTREAM_THROUGHOUT},
  };

  for (const auto& test : tests) {
    std::map<std::string, std::string> variation_params;
    if (test.set_variation_param)
      variation_params["effective_connection_type_algorithm"] = test.algorithm;

    TestNetworkQualityEstimator estimator(variation_params);
    EXPECT_EQ(test.expected_algorithm,
              estimator.effective_connection_type_algorithm_)
        << test.algorithm;
  }
}

// Tests that |GetEffectiveConnectionType| returns correct connection type when
// no variation params are specified.
TEST(NetworkQualityEstimatorTest, ObtainThresholdsNone) {
  std::map<std::string, std::string> variation_params;

  TestNetworkQualityEstimator estimator(variation_params);

  // Simulate the connection type as Wi-Fi so that GetEffectiveConnectionType
  // does not return Offline if the device is offline.
  estimator.SimulateNetworkChangeTo(NetworkChangeNotifier::CONNECTION_WIFI,
                                    "test");

  const struct {
    int32_t rtt_msec;
    NetworkQualityEstimator::EffectiveConnectionType expected_conn_type;
  } tests[] = {
      {5000, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_BROADBAND},
      {20, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_BROADBAND},
  };

  for (const auto& test : tests) {
    estimator.set_http_rtt(base::TimeDelta::FromMilliseconds(test.rtt_msec));
    estimator.set_recent_http_rtt(
        base::TimeDelta::FromMilliseconds(test.rtt_msec));
    estimator.set_downlink_throughput_kbps(INT32_MAX);
    estimator.set_recent_downlink_throughput_kbps(INT32_MAX);
    EXPECT_EQ(test.expected_conn_type, estimator.GetEffectiveConnectionType());
  }
}

// Tests that |GetEffectiveConnectionType| returns
// EFFECTIVE_CONNECTION_TYPE_OFFLINE when the device is currently offline.
TEST(NetworkQualityEstimatorTest, Offline) {
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);

  const struct {
    NetworkChangeNotifier::ConnectionType connection_type;
    NetworkQualityEstimator::EffectiveConnectionType expected_connection_type;
  } tests[] = {
      {NetworkChangeNotifier::CONNECTION_2G,
       NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_UNKNOWN},
      {NetworkChangeNotifier::CONNECTION_NONE,
       NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {NetworkChangeNotifier::CONNECTION_3G,
       NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_UNKNOWN},
  };

  for (const auto& test : tests) {
    estimator.SimulateNetworkChangeTo(test.connection_type, "test");
    EXPECT_EQ(test.expected_connection_type,
              estimator.GetEffectiveConnectionType());
  }
}

// Tests that |GetEffectiveConnectionType| returns correct connection type when
// only RTT thresholds are specified in the variation params.
TEST(NetworkQualityEstimatorTest, ObtainThresholdsOnlyRTT) {
  std::map<std::string, std::string> variation_params;

  variation_params["Offline.ThresholdMedianHttpRTTMsec"] = "4000";
  variation_params["Slow2G.ThresholdMedianHttpRTTMsec"] = "2000";
  variation_params["2G.ThresholdMedianHttpRTTMsec"] = "1000";
  variation_params["3G.ThresholdMedianHttpRTTMsec"] = "500";
  variation_params["4G.ThresholdMedianHttpRTTMsec"] = "300";
  variation_params["Broadband.ThresholdMedianHttpRTTMsec"] = "100";

  TestNetworkQualityEstimator estimator(variation_params);

  // Simulate the connection type as Wi-Fi so that GetEffectiveConnectionType
  // does not return Offline if the device is offline.
  estimator.SimulateNetworkChangeTo(NetworkChangeNotifier::CONNECTION_WIFI,
                                    "test");

  const struct {
    int32_t rtt_msec;
    NetworkQualityEstimator::EffectiveConnectionType expected_conn_type;
  } tests[] = {
      {5000, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {4000, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {3000, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {2000, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {1500, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_2G},
      {1000, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_2G},
      {700, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_3G},
      {500, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_3G},
      {400, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_4G},
      {300, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_4G},
      {200, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_BROADBAND},
      {100, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_BROADBAND},
      {20, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_BROADBAND},
  };

  for (const auto& test : tests) {
    estimator.set_http_rtt(base::TimeDelta::FromMilliseconds(test.rtt_msec));
    estimator.set_recent_http_rtt(
        base::TimeDelta::FromMilliseconds(test.rtt_msec));
    estimator.set_downlink_throughput_kbps(INT32_MAX);
    estimator.set_recent_downlink_throughput_kbps(INT32_MAX);
    EXPECT_EQ(test.expected_conn_type, estimator.GetEffectiveConnectionType());
  }
}

// Tests that |GetEffectiveConnectionType| returns correct connection type when
// both RTT and throughput thresholds are specified in the variation params.
TEST(NetworkQualityEstimatorTest, ObtainThresholdsRTTandThroughput) {
  std::map<std::string, std::string> variation_params;

  variation_params["Offline.ThresholdMedianHttpRTTMsec"] = "4000";
  variation_params["Slow2G.ThresholdMedianHttpRTTMsec"] = "2000";
  variation_params["2G.ThresholdMedianHttpRTTMsec"] = "1000";
  variation_params["3G.ThresholdMedianHttpRTTMsec"] = "500";
  variation_params["4G.ThresholdMedianHttpRTTMsec"] = "300";
  variation_params["Broadband.ThresholdMedianHttpRTTMsec"] = "100";

  variation_params["Offline.ThresholdMedianKbps"] = "10";
  variation_params["Slow2G.ThresholdMedianKbps"] = "100";
  variation_params["2G.ThresholdMedianKbps"] = "300";
  variation_params["3G.ThresholdMedianKbps"] = "500";
  variation_params["4G.ThresholdMedianKbps"] = "1000";
  variation_params["Broadband.ThresholdMedianKbps"] = "2000";

  TestNetworkQualityEstimator estimator(variation_params);

  // Simulate the connection type as Wi-Fi so that GetEffectiveConnectionType
  // does not return Offline if the device is offline.
  estimator.SimulateNetworkChangeTo(NetworkChangeNotifier::CONNECTION_WIFI,
                                    "test");

  const struct {
    int32_t rtt_msec;
    int32_t downlink_throughput_kbps;
    NetworkQualityEstimator::EffectiveConnectionType expected_conn_type;
  } tests[] = {
      // Set RTT to a very low value to observe the effect of throughput.
      // Throughput is the bottleneck.
      {1, 5, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {1, 10, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {1, 50, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {1, 100, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {1, 150, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_2G},
      {1, 300, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_2G},
      {1, 400, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_3G},
      {1, 500, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_3G},
      {1, 700, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_4G},
      {1, 1000, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_4G},
      {1, 1500, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_BROADBAND},
      {1, 2500, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_BROADBAND},
      // Set both RTT and throughput. RTT is the bottleneck.
      {3000, 25000, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {700, 25000, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_3G},
  };

  for (const auto& test : tests) {
    estimator.set_http_rtt(base::TimeDelta::FromMilliseconds(test.rtt_msec));
    estimator.set_recent_http_rtt(
        base::TimeDelta::FromMilliseconds(test.rtt_msec));
    estimator.set_downlink_throughput_kbps(test.downlink_throughput_kbps);
    estimator.set_recent_downlink_throughput_kbps(
        test.downlink_throughput_kbps);
    EXPECT_EQ(test.expected_conn_type, estimator.GetEffectiveConnectionType());
  }
}

// Tests if |weight_multiplier_per_second_| is set to correct value for various
// values of half life parameter.
TEST(NetworkQualityEstimatorTest, HalfLifeParam) {
  std::map<std::string, std::string> variation_params;

  const struct {
    std::string description;
    std::string variation_params_value;
    double expected_weight_multiplier;
  } tests[] = {
      {"Half life parameter is not set, default value should be used",
       std::string(), 0.988},
      {"Half life parameter is set to negative, default value should be used",
       "-100", 0.988},
      {"Half life parameter is set to zero, default value should be used", "0",
       0.988},
      {"Half life parameter is set correctly", "10", 0.933},
  };

  for (const auto& test : tests) {
    variation_params["HalfLifeSeconds"] = test.variation_params_value;
    TestNetworkQualityEstimator estimator(variation_params);
    EXPECT_NEAR(test.expected_weight_multiplier,
                estimator.weight_multiplier_per_second_, 0.001)
        << test.description;
  }
}

// Test if the network estimates are cached when network change notification
// is invoked.
TEST(NetworkQualityEstimatorTest, TestCaching) {
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);
  size_t expected_cache_size = 0;
  EXPECT_EQ(expected_cache_size, estimator.cached_network_qualities_.size());

  // Cache entry will not be added for (NONE, "").
  estimator.downstream_throughput_kbps_observations_.AddObservation(
      NetworkQualityEstimator::ThroughputObservation(
          1, base::TimeTicks::Now(),
          NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
  estimator.rtt_observations_.AddObservation(
      NetworkQualityEstimator::RttObservation(
          base::TimeDelta::FromMilliseconds(1000), base::TimeTicks::Now(),
          NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test-1");
  EXPECT_EQ(expected_cache_size, estimator.cached_network_qualities_.size());

  // Entry will be added for (2G, "test1").
  // Also, set the network quality for (2G, "test1") so that it is stored in
  // the cache.
  estimator.downstream_throughput_kbps_observations_.AddObservation(
      NetworkQualityEstimator::ThroughputObservation(
          1, base::TimeTicks::Now(),
          NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
  estimator.rtt_observations_.AddObservation(
      NetworkQualityEstimator::RttObservation(
          base::TimeDelta::FromMilliseconds(1000), base::TimeTicks::Now(),
          NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));

  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_3G, "test-1");
  ++expected_cache_size;
  EXPECT_EQ(expected_cache_size, estimator.cached_network_qualities_.size());

  // Entry will be added for (3G, "test1").
  // Also, set the network quality for (3G, "test1") so that it is stored in
  // the cache.
  estimator.downstream_throughput_kbps_observations_.AddObservation(
      NetworkQualityEstimator::ThroughputObservation(
          2, base::TimeTicks::Now(),
          NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
  estimator.rtt_observations_.AddObservation(
      NetworkQualityEstimator::RttObservation(
          base::TimeDelta::FromMilliseconds(500), base::TimeTicks::Now(),
          NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_3G, "test-2");
  ++expected_cache_size;
  EXPECT_EQ(expected_cache_size, estimator.cached_network_qualities_.size());

  // Entry will not be added for (3G, "test2").
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test-1");
  EXPECT_EQ(expected_cache_size, estimator.cached_network_qualities_.size());

  // Read the network quality for (2G, "test-1").
  EXPECT_TRUE(estimator.ReadCachedNetworkQualityEstimate());

  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_TRUE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  EXPECT_EQ(1, kbps);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(1000), rtt);
  EXPECT_FALSE(estimator.GetTransportRTTEstimate(&rtt));

  // No new entry should be added for (2G, "test-1") since it already exists
  // in the cache.
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_3G, "test-1");
  EXPECT_EQ(expected_cache_size, estimator.cached_network_qualities_.size());

  // Read the network quality for (3G, "test-1").
  EXPECT_TRUE(estimator.ReadCachedNetworkQualityEstimate());
  EXPECT_TRUE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  EXPECT_EQ(2, kbps);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(500), rtt);
  // No new entry should be added for (3G, "test1") since it already exists
  // in the cache.
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_3G, "test-2");
  EXPECT_EQ(expected_cache_size, estimator.cached_network_qualities_.size());

  // Reading quality of (3G, "test-2") should return false.
  EXPECT_FALSE(estimator.ReadCachedNetworkQualityEstimate());

  // Reading quality of (2G, "test-3") should return false.
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test-3");
  EXPECT_FALSE(estimator.ReadCachedNetworkQualityEstimate());
}

// Tests if the cache size remains bounded. Also, ensure that the cache is
// LRU.
TEST(NetworkQualityEstimatorTest, TestLRUCacheMaximumSize) {
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, std::string());
  EXPECT_EQ(0U, estimator.cached_network_qualities_.size());

  // Add 100 more networks than the maximum size of the cache.
  size_t network_count =
      NetworkQualityEstimator::kMaximumNetworkQualityCacheSize + 100;

  base::TimeTicks update_time_of_network_100;
  for (size_t i = 0; i < network_count; ++i) {
    estimator.downstream_throughput_kbps_observations_.AddObservation(
        NetworkQualityEstimator::ThroughputObservation(
            2, base::TimeTicks::Now(),
            NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
    estimator.rtt_observations_.AddObservation(
        NetworkQualityEstimator::RttObservation(
            base::TimeDelta::FromMilliseconds(500), base::TimeTicks::Now(),
            NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));

    if (i == 100)
      update_time_of_network_100 = base::TimeTicks::Now();

    estimator.SimulateNetworkChangeTo(
        NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI,
        base::SizeTToString(i));
    if (i < NetworkQualityEstimator::kMaximumNetworkQualityCacheSize)
      EXPECT_EQ(i, estimator.cached_network_qualities_.size());
    EXPECT_LE(estimator.cached_network_qualities_.size(),
              static_cast<size_t>(
                  NetworkQualityEstimator::kMaximumNetworkQualityCacheSize));
  }
  // One more call so that the last network is also written to cache.
  estimator.downstream_throughput_kbps_observations_.AddObservation(
      NetworkQualityEstimator::ThroughputObservation(
          2, base::TimeTicks::Now(),
          NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
  estimator.rtt_observations_.AddObservation(
      NetworkQualityEstimator::RttObservation(
          base::TimeDelta::FromMilliseconds(500), base::TimeTicks::Now(),
          NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI,
      base::SizeTToString(network_count - 1));
  EXPECT_EQ(static_cast<size_t>(
                NetworkQualityEstimator::kMaximumNetworkQualityCacheSize),
            estimator.cached_network_qualities_.size());

  // Test that the cache is LRU by examining its contents. Networks in cache
  // must all be newer than the 100th network.
  for (NetworkQualityEstimator::CachedNetworkQualities::iterator it =
           estimator.cached_network_qualities_.begin();
       it != estimator.cached_network_qualities_.end(); ++it) {
    EXPECT_GE((it->second).last_update_time_, update_time_of_network_100);
  }
}

TEST(NetworkQualityEstimatorTest, TestGetMetricsSince) {
  std::map<std::string, std::string> variation_params;

  const base::TimeDelta rtt_threshold_4g =
      base::TimeDelta::FromMilliseconds(30);
  const base::TimeDelta rtt_threshold_broadband =
      base::TimeDelta::FromMilliseconds(1);

  variation_params["4G.ThresholdMedianHttpRTTMsec"] =
      base::IntToString(rtt_threshold_4g.InMilliseconds());
  variation_params["Broadband.ThresholdMedianHttpRTTMsec"] =
      base::IntToString(rtt_threshold_broadband.InMilliseconds());
  variation_params["HalfLifeSeconds"] = "300000";

  TestNetworkQualityEstimator estimator(variation_params);
  base::TimeTicks now = base::TimeTicks::Now();
  base::TimeTicks old = now - base::TimeDelta::FromMilliseconds(1);
  ASSERT_NE(old, now);

  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test");

  const int32_t old_downlink_kbps = 1;
  const base::TimeDelta old_url_rtt = base::TimeDelta::FromMilliseconds(1);
  const base::TimeDelta old_tcp_rtt = base::TimeDelta::FromMilliseconds(10);

  DCHECK_LT(old_url_rtt, rtt_threshold_4g);
  DCHECK_LT(old_tcp_rtt, rtt_threshold_4g);

  // First sample has very old timestamp.
  for (size_t i = 0; i < 2; ++i) {
    estimator.downstream_throughput_kbps_observations_.AddObservation(
        NetworkQualityEstimator::ThroughputObservation(
            old_downlink_kbps, old,
            NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
    estimator.rtt_observations_.AddObservation(
        NetworkQualityEstimator::RttObservation(
            old_url_rtt, old, NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
    estimator.rtt_observations_.AddObservation(
        NetworkQualityEstimator::RttObservation(
            old_tcp_rtt, old, NETWORK_QUALITY_OBSERVATION_SOURCE_TCP));
  }

  const int32_t new_downlink_kbps = 100;
  const base::TimeDelta new_url_rtt = base::TimeDelta::FromMilliseconds(100);
  const base::TimeDelta new_tcp_rtt = base::TimeDelta::FromMilliseconds(1000);

  DCHECK_NE(old_downlink_kbps, new_downlink_kbps);
  DCHECK_NE(old_url_rtt, new_url_rtt);
  DCHECK_NE(old_tcp_rtt, new_tcp_rtt);
  DCHECK_GT(new_url_rtt, rtt_threshold_4g);
  DCHECK_GT(new_tcp_rtt, rtt_threshold_4g);
  DCHECK_GT(new_url_rtt, rtt_threshold_broadband);
  DCHECK_GT(new_tcp_rtt, rtt_threshold_broadband);

  estimator.downstream_throughput_kbps_observations_.AddObservation(
      NetworkQualityEstimator::ThroughputObservation(
          new_downlink_kbps, now,
          NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
  estimator.rtt_observations_.AddObservation(
      NetworkQualityEstimator::RttObservation(
          new_url_rtt, now, NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
  estimator.rtt_observations_.AddObservation(
      NetworkQualityEstimator::RttObservation(
          new_tcp_rtt, now, NETWORK_QUALITY_OBSERVATION_SOURCE_TCP));

  const struct {
    base::TimeTicks start_timestamp;
    bool expect_network_quality_available;
    base::TimeDelta expected_http_rtt;
    base::TimeDelta expected_transport_rtt;
    int32_t expected_downstream_throughput;
    NetworkQualityEstimator::EffectiveConnectionType
        expected_effective_connection_type;
  } tests[] = {
      {now + base::TimeDelta::FromSeconds(10), false,
       base::TimeDelta::FromMilliseconds(0),
       base::TimeDelta::FromMilliseconds(0), 0,
       NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_BROADBAND},
      {now, true, new_url_rtt, new_tcp_rtt, new_downlink_kbps,
       NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_4G},
      {old - base::TimeDelta::FromMicroseconds(500), true, old_url_rtt,
       old_tcp_rtt, old_downlink_kbps,
       NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_BROADBAND},

  };
  for (const auto& test : tests) {
    base::TimeDelta http_rtt;
    base::TimeDelta transport_rtt;
    int32_t downstream_throughput_kbps;
    EXPECT_EQ(
        test.expect_network_quality_available,
        estimator.GetRecentHttpRTTMedian(test.start_timestamp, &http_rtt));
    EXPECT_EQ(test.expect_network_quality_available,
              estimator.GetRecentTransportRTTMedian(test.start_timestamp,
                                                    &transport_rtt));
    EXPECT_EQ(test.expect_network_quality_available,
              estimator.GetRecentMedianDownlinkThroughputKbps(
                  test.start_timestamp, &downstream_throughput_kbps));

    if (test.expect_network_quality_available) {
      EXPECT_EQ(test.expected_http_rtt, http_rtt);
      EXPECT_EQ(test.expected_transport_rtt, transport_rtt);
      EXPECT_EQ(test.expected_downstream_throughput,
                downstream_throughput_kbps);
      EXPECT_EQ(
          test.expected_effective_connection_type,
          estimator.GetRecentEffectiveConnectionType(test.start_timestamp));
    }
  }
}

// An external estimate provider that does not have a valid RTT or throughput
// estimate.
class InvalidExternalEstimateProvider : public ExternalEstimateProvider {
 public:
  InvalidExternalEstimateProvider() : update_count_(0) {}
  ~InvalidExternalEstimateProvider() override {}

  bool GetRTT(base::TimeDelta* rtt) const override {
    DCHECK(rtt);
    return false;
  }

  bool GetDownstreamThroughputKbps(
      int32_t* downstream_throughput_kbps) const override {
    DCHECK(downstream_throughput_kbps);
    return false;
  }

  bool GetUpstreamThroughputKbps(
      int32_t* upstream_throughput_kbps) const override {
    // NetworkQualityEstimator does not support upstream throughput.
    ADD_FAILURE();
    return false;
  }

  bool GetTimeSinceLastUpdate(
      base::TimeDelta* time_since_last_update) const override {
    NOTREACHED();
    return false;
  }

  void SetUpdatedEstimateDelegate(UpdatedEstimateDelegate* delegate) override {}

  void Update() const override { update_count_++; }

  size_t update_count() const { return update_count_; }

 private:
  mutable size_t update_count_;

  DISALLOW_COPY_AND_ASSIGN(InvalidExternalEstimateProvider);
};

// Tests if the RTT value from external estimate provider is discarded if the
// external estimate provider is invalid.
TEST(NetworkQualityEstimatorTest, InvalidExternalEstimateProvider) {
  base::HistogramTester histogram_tester;
  InvalidExternalEstimateProvider* invalid_external_estimate_provider =
      new InvalidExternalEstimateProvider();
  std::unique_ptr<ExternalEstimateProvider> external_estimate_provider(
      invalid_external_estimate_provider);

  TestNetworkQualityEstimator estimator(std::map<std::string, std::string>(),
                                        std::move(external_estimate_provider));
  estimator.SimulateNetworkChangeTo(net::NetworkChangeNotifier::CONNECTION_WIFI,
                                    "test");

  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_EQ(1U, invalid_external_estimate_provider->update_count());
  EXPECT_FALSE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  histogram_tester.ExpectTotalCount("NQE.ExternalEstimateProviderStatus", 2);

  histogram_tester.ExpectBucketCount(
      "NQE.ExternalEstimateProviderStatus",
      1 /* EXTERNAL_ESTIMATE_PROVIDER_STATUS_AVAILABLE */, 1);
  histogram_tester.ExpectBucketCount(
      "NQE.ExternalEstimateProviderStatus",
      2 /* EXTERNAL_ESTIMATE_PROVIDER_STATUS_QUERIED */, 1);
  histogram_tester.ExpectTotalCount("NQE.ExternalEstimateProvider.RTT", 0);
  histogram_tester.ExpectTotalCount(
      "NQE.ExternalEstimateProvider.DownlinkBandwidth", 0);
}

class TestExternalEstimateProvider : public ExternalEstimateProvider {
 public:
  TestExternalEstimateProvider(base::TimeDelta rtt,
                               int32_t downstream_throughput_kbps)
      : delegate_(nullptr),
        should_notify_delegate_(true),
        rtt_(rtt),
        downstream_throughput_kbps_(downstream_throughput_kbps),
        update_count_(0) {}
  ~TestExternalEstimateProvider() override {}

  bool GetRTT(base::TimeDelta* rtt) const override {
    NOTREACHED();
    return true;
  }

  bool GetDownstreamThroughputKbps(
      int32_t* downstream_throughput_kbps) const override {
    NOTREACHED();
    return true;
  }

  bool GetUpstreamThroughputKbps(
      int32_t* upstream_throughput_kbps) const override {
    NOTREACHED();
    return false;
  }

  bool GetTimeSinceLastUpdate(
      base::TimeDelta* time_since_last_update) const override {
    NOTREACHED();
    return true;
  }

  void SetUpdatedEstimateDelegate(UpdatedEstimateDelegate* delegate) override {
    delegate_ = delegate;
  }

  void set_should_notify_delegate(bool should_notify_delegate) {
    should_notify_delegate_ = should_notify_delegate;
  }

  void Update() const override {
    update_count_++;
    if (!should_notify_delegate_)
      return;
    delegate_->OnUpdatedEstimateAvailable(rtt_, downstream_throughput_kbps_,
                                          -1);
  }

  size_t update_count() const { return update_count_; }

 private:
  UpdatedEstimateDelegate* delegate_;

  bool should_notify_delegate_;

  // RTT and downstream throughput estimates.
  const base::TimeDelta rtt_;
  const int32_t downstream_throughput_kbps_;

  mutable size_t update_count_;

  DISALLOW_COPY_AND_ASSIGN(TestExternalEstimateProvider);
};

// Tests if the external estimate provider is called in the constructor and
// on network change notification.
TEST(NetworkQualityEstimatorTest, TestExternalEstimateProvider) {
  base::HistogramTester histogram_tester;
  const base::TimeDelta external_estimate_provider_rtt =
      base::TimeDelta::FromMilliseconds(1);
  const int32_t external_estimate_provider_downstream_throughput = 100;

  TestExternalEstimateProvider* test_external_estimate_provider =
      new TestExternalEstimateProvider(
          external_estimate_provider_rtt,
          external_estimate_provider_downstream_throughput);
  std::unique_ptr<ExternalEstimateProvider> external_estimate_provider(
      test_external_estimate_provider);
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params,
                                        std::move(external_estimate_provider));
  estimator.SimulateNetworkChangeTo(net::NetworkChangeNotifier::CONNECTION_WIFI,
                                    "test");
  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_TRUE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_FALSE(estimator.GetTransportRTTEstimate(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));

  histogram_tester.ExpectTotalCount("NQE.ExternalEstimateProviderStatus", 5);

  histogram_tester.ExpectBucketCount(
      "NQE.ExternalEstimateProviderStatus",
      1 /* EXTERNAL_ESTIMATE_PROVIDER_STATUS_AVAILABLE */, 1);
  histogram_tester.ExpectBucketCount(
      "NQE.ExternalEstimateProviderStatus",
      2 /* EXTERNAL_ESTIMATE_PROVIDER_STATUS_QUERIED */, 1);
  histogram_tester.ExpectBucketCount(
      "NQE.ExternalEstimateProviderStatus",
      4 /* EXTERNAL_ESTIMATE_PROVIDER_STATUS_CALLBACK */, 1);
  histogram_tester.ExpectBucketCount(
      "NQE.ExternalEstimateProviderStatus",
      5 /* EXTERNAL_ESTIMATE_PROVIDER_STATUS_RTT_AVAILABLE */, 1);
  histogram_tester.ExpectBucketCount(
      "NQE.ExternalEstimateProviderStatus",
      6 /* EXTERNAL_ESTIMATE_PROVIDER_STATUS_DOWNLINK_BANDWIDTH_AVAILABLE */,
      1);
  histogram_tester.ExpectUniqueSample("NQE.ExternalEstimateProvider.RTT", 1, 1);
  histogram_tester.ExpectUniqueSample(
      "NQE.ExternalEstimateProvider.DownlinkBandwidth", 100, 1);

  EXPECT_EQ(1U, test_external_estimate_provider->update_count());

  // Change network type to WiFi. Number of queries to External estimate
  // provider must increment.
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-1");
  EXPECT_TRUE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  EXPECT_EQ(2U, test_external_estimate_provider->update_count());

  test_external_estimate_provider->set_should_notify_delegate(false);
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test-2");
  EXPECT_EQ(3U, test_external_estimate_provider->update_count());
  // Estimates are unavailable because external estimate provider never
  // notifies network quality estimator of the updated estimates.
  EXPECT_FALSE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
}

// Tests if the estimate from the external estimate provider is merged with the
// observations collected from the HTTP requests.
TEST(NetworkQualityEstimatorTest, TestExternalEstimateProviderMergeEstimates) {
  const base::TimeDelta external_estimate_provider_rtt =
      base::TimeDelta::FromMilliseconds(10 * 1000);
  const int32_t external_estimate_provider_downstream_throughput = 100 * 1000;
  TestExternalEstimateProvider* test_external_estimate_provider =
      new TestExternalEstimateProvider(
          external_estimate_provider_rtt,
          external_estimate_provider_downstream_throughput);
  std::unique_ptr<ExternalEstimateProvider> external_estimate_provider(
      test_external_estimate_provider);

  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params,
                                        std::move(external_estimate_provider));
  estimator.SimulateNetworkChangeTo(net::NetworkChangeNotifier::CONNECTION_WIFI,
                                    "test");

  base::TimeDelta rtt;
  // Estimate provided by network quality estimator should match the estimate
  // provided by external estimate provider.
  EXPECT_TRUE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_EQ(external_estimate_provider_rtt, rtt);

  int32_t kbps;
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  EXPECT_EQ(external_estimate_provider_downstream_throughput, kbps);

  TestDelegate test_delegate;
  TestURLRequestContext context(true);
  context.set_network_quality_estimator(&estimator);
  context.Init();

  std::unique_ptr<URLRequest> request(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request->Start();
  base::RunLoop().Run();

  EXPECT_TRUE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_NE(external_estimate_provider_rtt, rtt);

  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  EXPECT_NE(external_estimate_provider_downstream_throughput, kbps);
}

// Tests if the throughput observation is taken correctly when local and network
// requests do not overlap.
TEST(NetworkQualityEstimatorTest, TestThroughputNoRequestOverlap) {
  base::HistogramTester histogram_tester;
  std::map<std::string, std::string> variation_params;

  static const struct {
    bool allow_small_localhost_requests;
  } tests[] = {
      {
          false,
      },
      {
          true,
      },
  };

  for (const auto& test : tests) {
    TestNetworkQualityEstimator estimator(
        std::unique_ptr<net::ExternalEstimateProvider>(), variation_params,
        test.allow_small_localhost_requests,
        test.allow_small_localhost_requests);

    base::TimeDelta rtt;
    EXPECT_FALSE(estimator.GetHttpRTTEstimate(&rtt));
    int32_t kbps;
    EXPECT_FALSE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));

    TestDelegate test_delegate;
    TestURLRequestContext context(true);
    context.set_network_quality_estimator(&estimator);
    context.Init();

    std::unique_ptr<URLRequest> request(context.CreateRequest(
        estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
    request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME);
    request->Start();
    base::RunLoop().Run();

    EXPECT_EQ(test.allow_small_localhost_requests,
              estimator.GetHttpRTTEstimate(&rtt));
    EXPECT_EQ(test.allow_small_localhost_requests,
              estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  }
}

// Tests that the effective connection type is computed at the specified
// interval, and that the observers are notified of any change.
TEST(NetworkQualityEstimatorTest, TestEffectiveConnectionTypeObserver) {
  base::HistogramTester histogram_tester;
  std::unique_ptr<base::SimpleTestTickClock> tick_clock(
      new base::SimpleTestTickClock());
  base::SimpleTestTickClock* tick_clock_ptr = tick_clock.get();

  TestEffectiveConnectionTypeObserver observer;
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.AddEffectiveConnectionTypeObserver(&observer);
  estimator.SetTickClockForTesting(std::move(tick_clock));

  TestDelegate test_delegate;
  TestURLRequestContext context(true);
  context.set_network_quality_estimator(&estimator);
  context.Init();

  EXPECT_EQ(0U, observer.effective_connection_types().size());

  estimator.set_effective_connection_type(
      NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_2G);
  tick_clock_ptr->Advance(base::TimeDelta::FromMinutes(60));

  std::unique_ptr<URLRequest> request(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME);
  request->Start();
  base::RunLoop().Run();
  EXPECT_EQ(1U, observer.effective_connection_types().size());
  histogram_tester.ExpectUniqueSample(
      "NQE.MainFrame.EffectiveConnectionType.Unknown",
      NetworkQualityEstimator::EffectiveConnectionType::
          EFFECTIVE_CONNECTION_TYPE_2G,
      1);

  // Next request should not trigger recomputation of effective connection type
  // since there has been no change in the clock.
  std::unique_ptr<URLRequest> request2(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request2->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME);
  request2->Start();
  base::RunLoop().Run();
  EXPECT_EQ(1U, observer.effective_connection_types().size());

  // Change in connection type should send out notification to the observers.
  estimator.set_effective_connection_type(
      NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_3G);
  estimator.SimulateNetworkChangeTo(NetworkChangeNotifier::CONNECTION_WIFI,
                                    "test");
  EXPECT_EQ(2U, observer.effective_connection_types().size());

  // A change in effective connection type does not trigger notification to the
  // observers, since it is not accompanied by any new observation or a network
  // change event.
  estimator.set_effective_connection_type(
      NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_3G);
  EXPECT_EQ(2U, observer.effective_connection_types().size());
}

TEST(NetworkQualityEstimatorTest, TestRttThroughputObservers) {
  TestRTTObserver rtt_observer;
  TestThroughputObserver throughput_observer;
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.AddRTTObserver(&rtt_observer);
  estimator.AddThroughputObserver(&throughput_observer);

  TestDelegate test_delegate;
  TestURLRequestContext context(true);
  context.set_network_quality_estimator(&estimator);
  context.Init();

  EXPECT_EQ(0U, rtt_observer.observations().size());
  EXPECT_EQ(0U, throughput_observer.observations().size());
  base::TimeTicks then = base::TimeTicks::Now();

  std::unique_ptr<URLRequest> request(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME);
  request->Start();
  base::RunLoop().Run();

  std::unique_ptr<URLRequest> request2(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request2->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME);
  request2->Start();
  base::RunLoop().Run();

  // Both RTT and downstream throughput should be updated.
  base::TimeDelta rtt;
  EXPECT_TRUE(estimator.GetHttpRTTEstimate(&rtt));

  int32_t throughput;
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&throughput));

  EXPECT_EQ(2U, rtt_observer.observations().size());
  EXPECT_EQ(2U, throughput_observer.observations().size());
  for (const auto& observation : rtt_observer.observations()) {
    EXPECT_LE(0, observation.rtt_ms);
    EXPECT_LE(0, (observation.timestamp - then).InMilliseconds());
    EXPECT_EQ(NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST,
              observation.source);
  }
  for (const auto& observation : throughput_observer.observations()) {
    EXPECT_LE(0, observation.throughput_kbps);
    EXPECT_LE(0, (observation.timestamp - then).InMilliseconds());
    EXPECT_EQ(NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST,
              observation.source);
  }

  EXPECT_FALSE(estimator.GetTransportRTTEstimate(&rtt));

  // Verify that observations from TCP and QUIC are passed on to the observers.
  base::TimeDelta tcp_rtt(base::TimeDelta::FromMilliseconds(1));
  base::TimeDelta quic_rtt(base::TimeDelta::FromMilliseconds(2));

  std::unique_ptr<SocketPerformanceWatcher> tcp_watcher =
      estimator.GetSocketPerformanceWatcherFactory()
          ->CreateSocketPerformanceWatcher(
              SocketPerformanceWatcherFactory::PROTOCOL_TCP);

  std::unique_ptr<SocketPerformanceWatcher> quic_watcher =
      estimator.GetSocketPerformanceWatcherFactory()
          ->CreateSocketPerformanceWatcher(
              SocketPerformanceWatcherFactory::PROTOCOL_QUIC);

  tcp_watcher->OnUpdatedRTTAvailable(tcp_rtt);
  quic_watcher->OnUpdatedRTTAvailable(quic_rtt);

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(4U, rtt_observer.observations().size());
  EXPECT_EQ(2U, throughput_observer.observations().size());

  EXPECT_EQ(tcp_rtt.InMilliseconds(), rtt_observer.observations().at(2).rtt_ms);
  EXPECT_EQ(quic_rtt.InMilliseconds(),
            rtt_observer.observations().at(3).rtt_ms);

  EXPECT_TRUE(estimator.GetTransportRTTEstimate(&rtt));
}

// TestTCPSocketRTT requires kernel support for tcp_info struct, and so it is
// enabled only on certain platforms.
#if defined(TCP_INFO) || defined(OS_LINUX)
#define MAYBE_TestTCPSocketRTT TestTCPSocketRTT
#else
#define MAYBE_TestTCPSocketRTT DISABLED_TestTCPSocketRTT
#endif
// Tests that the TCP socket notifies the Network Quality Estimator of TCP RTTs,
// which in turn notifies registered RTT observers.
TEST(NetworkQualityEstimatorTest, MAYBE_TestTCPSocketRTT) {
  base::HistogramTester histogram_tester;
  TestRTTObserver rtt_observer;
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.AddRTTObserver(&rtt_observer);

  TestDelegate test_delegate;
  TestURLRequestContext context(true);
  context.set_network_quality_estimator(&estimator);

  std::unique_ptr<HttpNetworkSession::Params> params(
      new HttpNetworkSession::Params);
  // |estimator| should be notified of TCP RTT observations.
  params->socket_performance_watcher_factory =
      estimator.GetSocketPerformanceWatcherFactory();
  context.set_http_network_session_params(std::move(params));
  context.Init();

  EXPECT_EQ(0U, rtt_observer.observations().size());
  base::TimeDelta rtt;
  EXPECT_FALSE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_FALSE(estimator.GetTransportRTTEstimate(&rtt));

  // Send two requests. Verify that the completion of each request generates at
  // least one TCP RTT observation.
  const size_t num_requests = 2;
  for (size_t i = 0; i < num_requests; ++i) {
    size_t before_count_tcp_rtt_observations = 0;
    for (const auto& observation : rtt_observer.observations()) {
      if (observation.source == NETWORK_QUALITY_OBSERVATION_SOURCE_TCP)
        ++before_count_tcp_rtt_observations;
    }

    std::unique_ptr<URLRequest> request(context.CreateRequest(
        estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
    request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME);
    request->Start();
    base::RunLoop().Run();

    size_t after_count_tcp_rtt_observations = 0;
    for (const auto& observation : rtt_observer.observations()) {
      if (observation.source == NETWORK_QUALITY_OBSERVATION_SOURCE_TCP)
        ++after_count_tcp_rtt_observations;
    }
    // At least one notification should be received per socket performance
    // watcher.
    EXPECT_LE(1U, after_count_tcp_rtt_observations -
                      before_count_tcp_rtt_observations)
        << i;
  }
  EXPECT_TRUE(estimator.GetHttpRTTEstimate(&rtt));
  EXPECT_TRUE(estimator.GetTransportRTTEstimate(&rtt));

  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-1");
  histogram_tester.ExpectTotalCount("NQE.TransportRTT.Percentile50.Unknown", 1);
  histogram_tester.ExpectBucketCount("NQE.TransportRTT.Percentile50.Unknown",
                                     rtt.InMilliseconds(), 1);
  histogram_tester.ExpectTotalCount("NQE.TransportRTT.Percentile10.Unknown", 1);
  histogram_tester.ExpectTotalCount("NQE.TransportRTT.Percentile50.Unknown", 1);
  histogram_tester.ExpectTotalCount("NQE.TransportRTT.Percentile90.Unknown", 1);
  histogram_tester.ExpectTotalCount("NQE.TransportRTT.Percentile100.Unknown",
                                    1);

  // Verify that metrics are logged correctly on main-frame requests.
  histogram_tester.ExpectTotalCount(
      "NQE.MainFrame.TransportRTT.Percentile50.Unknown", num_requests);
  histogram_tester.ExpectTotalCount(
      "NQE.MainFrame.EffectiveConnectionType.Unknown", num_requests);
  histogram_tester.ExpectBucketCount(
      "NQE.MainFrame.EffectiveConnectionType.Unknown",
      NetworkQualityEstimator::EffectiveConnectionType::
          EFFECTIVE_CONNECTION_TYPE_UNKNOWN,
      1);
}

#if defined(OS_IOS)
// Flaky on iOS when |accuracy_recording_delay| is non-zero.
#define MAYBE_RecordAccuracy DISABLED_RecordAccuracy
#else
#define MAYBE_RecordAccuracy RecordAccuracy
#endif
// Tests if the NQE accuracy metrics are recorded properly.
TEST(NetworkQualityEstimatorTest, MAYBE_RecordAccuracy) {
  const int expected_rtt_msec = 100;
  const int expected_downstream_throughput_kbps = 200;

  const base::TimeDelta accuracy_recording_delays[] = {
      base::TimeDelta::FromSeconds(0), base::TimeDelta::FromSeconds(1),
  };

  const struct {
    base::TimeDelta rtt;
    base::TimeDelta recent_rtt;
    int32_t downstream_throughput_kbps;
    int32_t recent_downstream_throughput_kbps;
    NetworkQualityEstimator::EffectiveConnectionType effective_connection_type;
    NetworkQualityEstimator::EffectiveConnectionType
        recent_effective_connection_type;
  } tests[] = {
      {base::TimeDelta::FromMilliseconds(expected_rtt_msec),
       base::TimeDelta::FromMilliseconds(expected_rtt_msec),
       expected_downstream_throughput_kbps, expected_downstream_throughput_kbps,
       NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_2G,
       NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_2G},

      {
          base::TimeDelta::FromMilliseconds(expected_rtt_msec + 1),
          base::TimeDelta::FromMilliseconds(expected_rtt_msec),
          expected_downstream_throughput_kbps + 1,
          expected_downstream_throughput_kbps,
          NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_3G,
          NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_2G,
      },
      {
          base::TimeDelta::FromMilliseconds(expected_rtt_msec - 1),
          base::TimeDelta::FromMilliseconds(expected_rtt_msec),
          expected_downstream_throughput_kbps - 1,
          expected_downstream_throughput_kbps,
          NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_SLOW_2G,
          NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_2G,
      },
  };

  for (const auto& accuracy_recording_delay : accuracy_recording_delays) {
    for (const auto& test : tests) {
      std::unique_ptr<base::SimpleTestTickClock> tick_clock(
          new base::SimpleTestTickClock());
      base::SimpleTestTickClock* tick_clock_ptr = tick_clock.get();
      tick_clock_ptr->Advance(base::TimeDelta::FromSeconds(1));

      std::map<std::string, std::string> variation_params;
      TestNetworkQualityEstimator estimator(variation_params);
      estimator.SetTickClockForTesting(std::move(tick_clock));
      estimator.SimulateNetworkChangeTo(
          NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-1");
      tick_clock_ptr->Advance(base::TimeDelta::FromSeconds(1));

      std::vector<base::TimeDelta> accuracy_recording_intervals;
      accuracy_recording_intervals.push_back(accuracy_recording_delay);
      estimator.SetAccuracyRecordingIntervals(accuracy_recording_intervals);

      // RTT is higher than threshold. Network is slow.
      // Network was predicted to be slow and actually was slow.
      estimator.set_http_rtt(test.rtt);
      estimator.set_recent_http_rtt(test.recent_rtt);
      estimator.set_transport_rtt(test.rtt);
      estimator.set_recent_transport_rtt(test.recent_rtt);
      estimator.set_downlink_throughput_kbps(test.downstream_throughput_kbps);
      estimator.set_recent_downlink_throughput_kbps(
          test.recent_downstream_throughput_kbps);
      estimator.set_effective_connection_type(test.effective_connection_type);
      estimator.set_recent_effective_connection_type(
          test.recent_effective_connection_type);

      base::HistogramTester histogram_tester;

      TestDelegate test_delegate;
      TestURLRequestContext context(true);
      context.set_network_quality_estimator(&estimator);
      context.Init();

      // Start a main-frame request which should cause network quality estimator
      // to record accuracy UMA.
      std::unique_ptr<URLRequest> request(context.CreateRequest(
          estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
      request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME);
      request->Start();
      base::RunLoop().Run();

      if (accuracy_recording_delay != base::TimeDelta()) {
        tick_clock_ptr->Advance(accuracy_recording_delay);

        // Sleep for some time to ensure that the delayed task is posted.
        base::PlatformThread::Sleep(accuracy_recording_delay * 2);
        base::RunLoop().RunUntilIdle();
      }

      const int diff = std::abs(test.rtt.InMilliseconds() -
                                test.recent_rtt.InMilliseconds());
      const std::string sign_suffix_with_one_sample =
          test.rtt.InMilliseconds() - test.recent_rtt.InMilliseconds() >= 0
              ? "Positive"
              : "Negative";
      const std::string sign_suffix_with_zero_samples =
          test.rtt.InMilliseconds() - test.recent_rtt.InMilliseconds() >= 0
              ? "Negative"
              : "Positive";
      const std::string interval_value =
          base::IntToString(accuracy_recording_delay.InSeconds());

      histogram_tester.ExpectUniqueSample(
          "NQE.Accuracy.DownstreamThroughputKbps.EstimatedObservedDiff." +
              sign_suffix_with_one_sample + "." + interval_value + ".140_300",
          diff, 1);
      histogram_tester.ExpectTotalCount(
          "NQE.Accuracy.DownstreamThroughputKbps.EstimatedObservedDiff." +
              sign_suffix_with_zero_samples + "." + interval_value + ".140_300",
          0);

      histogram_tester.ExpectUniqueSample(
          "NQE.Accuracy.EffectiveConnectionType.EstimatedObservedDiff." +
              sign_suffix_with_one_sample + "." + interval_value + ".2G",
          diff, 1);
      histogram_tester.ExpectTotalCount(
          "NQE.Accuracy.EffectiveConnectionType.EstimatedObservedDiff." +
              sign_suffix_with_zero_samples + "." + interval_value + ".2G",
          0);

      histogram_tester.ExpectUniqueSample(
          "NQE.Accuracy.HttpRTT.EstimatedObservedDiff." +
              sign_suffix_with_one_sample + "." + interval_value + ".60_140",
          diff, 1);
      histogram_tester.ExpectTotalCount(
          "NQE.Accuracy.HttpRTT.EstimatedObservedDiff." +
              sign_suffix_with_zero_samples + "." + interval_value + ".60_140",
          0);
      histogram_tester.ExpectUniqueSample(
          "NQE.Accuracy.TransportRTT.EstimatedObservedDiff." +
              sign_suffix_with_one_sample + "." + interval_value + ".60_140",
          diff, 1);
      histogram_tester.ExpectTotalCount(
          "NQE.Accuracy.TransportRTT.EstimatedObservedDiff." +
              sign_suffix_with_zero_samples + "." + interval_value + ".60_140",
          0);
    }
  }
}

// Tests that the effective connection type is converted correctly to a
// descriptive string name, and vice-versa.
TEST(NetworkQualityEstimatorTest, NameConnectionTypeConversion) {
  for (size_t i = 0;
       i < NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_LAST; ++i) {
    const NetworkQualityEstimator::EffectiveConnectionType
        effective_connection_type =
            static_cast<NetworkQualityEstimator::EffectiveConnectionType>(i);
    std::string connection_type_name =
        std::string(NetworkQualityEstimator::GetNameForEffectiveConnectionType(
            effective_connection_type));
    EXPECT_FALSE(connection_type_name.empty());
    EXPECT_EQ(effective_connection_type,
              NetworkQualityEstimator::GetEffectiveConnectionTypeForName(
                  connection_type_name));
  }
}

}  // namespace net

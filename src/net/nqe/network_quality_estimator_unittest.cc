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
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/load_flags.h"
#include "net/base/network_change_notifier.h"
#include "net/http/http_status_code.h"
#include "net/nqe/external_estimate_provider.h"
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
      std::unique_ptr<ExternalEstimateProvider> external_estimate_provider)
      : NetworkQualityEstimator(std::move(external_estimate_provider),
                                variation_params,
                                true,
                                true),
        url_rtt_set_(false),
        downlink_throughput_kbps_set_(false) {
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
                               std::string network_id) {
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

  void set_url_rtt(const base::TimeDelta& url_rtt) {
    url_rtt_set_ = true;
    url_rtt_ = url_rtt;
  }

  bool GetURLRequestRTTEstimate(base::TimeDelta* rtt) const override {
    if (url_rtt_set_) {
      *rtt = url_rtt_;
      return true;
    }
    return NetworkQualityEstimator::GetURLRequestRTTEstimate(rtt);
  }

  void set_downlink_throughput_kbps(int32_t downlink_throughput_kbps) {
    downlink_throughput_kbps_set_ = true;
    downlink_throughput_kbps_ = downlink_throughput_kbps;
  }

  bool GetDownlinkThroughputKbpsEstimate(int32_t* kbps) const override {
    if (downlink_throughput_kbps_set_) {
      *kbps = downlink_throughput_kbps_;
      return true;
    }
    return NetworkQualityEstimator::GetDownlinkThroughputKbpsEstimate(kbps);
  }

  using NetworkQualityEstimator::ReadCachedNetworkQualityEstimate;
  using NetworkQualityEstimator::OnConnectionTypeChanged;

 private:
  // NetworkQualityEstimator implementation that returns the overridden network
  // id (instead of invoking platform APIs).
  NetworkQualityEstimator::NetworkID GetCurrentNetworkID() const override {
    return NetworkQualityEstimator::NetworkID(current_network_type_,
                                              current_network_id_);
  }

  NetworkChangeNotifier::ConnectionType current_network_type_;
  std::string current_network_id_;

  bool url_rtt_set_;
  base::TimeDelta url_rtt_;

  bool downlink_throughput_kbps_set_;
  int32_t downlink_throughput_kbps_;

  // Embedded server used for testing.
  EmbeddedTestServer embedded_test_server_;

  DISALLOW_COPY_AND_ASSIGN(TestNetworkQualityEstimator);
};

class TestRTTObserver : public NetworkQualityEstimator::RTTObserver {
 public:
  struct Observation {
    Observation(int32_t ms,
                const base::TimeTicks& ts,
                NetworkQualityEstimator::ObservationSource src)
        : rtt_ms(ms), timestamp(ts), source(src) {}
    int32_t rtt_ms;
    base::TimeTicks timestamp;
    NetworkQualityEstimator::ObservationSource source;
  };

  std::vector<Observation>& observations() { return observations_; }

  // RttObserver implementation:
  void OnRTTObservation(
      int32_t rtt_ms,
      const base::TimeTicks& timestamp,
      NetworkQualityEstimator::ObservationSource source) override {
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
                NetworkQualityEstimator::ObservationSource src)
        : throughput_kbps(kbps), timestamp(ts), source(src) {}
    int32_t throughput_kbps;
    base::TimeTicks timestamp;
    NetworkQualityEstimator::ObservationSource source;
  };

  std::vector<Observation>& observations() { return observations_; }

  // ThroughputObserver implementation:
  void OnThroughputObservation(
      int32_t throughput_kbps,
      const base::TimeTicks& timestamp,
      NetworkQualityEstimator::ObservationSource source) override {
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
  EXPECT_FALSE(estimator.GetURLRequestRTTEstimate(&rtt));
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
  EXPECT_TRUE(estimator.GetURLRequestRTTEstimate(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));

  EXPECT_TRUE(estimator.GetURLRequestRTTEstimate(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));

  // Check UMA histograms.
  histogram_tester.ExpectTotalCount("NQE.PeakKbps.Unknown", 0);
  histogram_tester.ExpectTotalCount("NQE.FastestRTT.Unknown", 0);

  histogram_tester.ExpectTotalCount("NQE.RatioEstimatedToActualRTT.Unknown", 0);

  std::unique_ptr<URLRequest> request2(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request2->SetLoadFlags(request2->load_flags() | LOAD_MAIN_FRAME);
  request2->Start();
  base::RunLoop().Run();

  histogram_tester.ExpectTotalCount("NQE.RTTObservations.Unknown", 1);
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

  EXPECT_FALSE(estimator.GetURLRequestRTTEstimate(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));

  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, std::string());
  histogram_tester.ExpectTotalCount("NQE.PeakKbps.Unknown", 1);
  histogram_tester.ExpectTotalCount("NQE.FastestRTT.Unknown", 1);

  EXPECT_FALSE(estimator.GetURLRequestRTTEstimate(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
}

TEST(NetworkQualityEstimatorTest, StoreObservations) {
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);

  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_FALSE(estimator.GetURLRequestRTTEstimate(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));

  TestDelegate test_delegate;
  TestURLRequestContext context(true);
  context.set_network_quality_estimator(&estimator);
  context.Init();

  // Push 10 more observations than the maximum buffer size.
  for (size_t i = 0; i < estimator.kMaximumObservationsBufferSize + 10U; ++i) {
    std::unique_ptr<URLRequest> request(context.CreateRequest(
        estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
    request->Start();
    base::RunLoop().Run();
    EXPECT_TRUE(estimator.GetURLRequestRTTEstimate(&rtt));
    EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  }

  // Verify that the stored observations are cleared on network change.
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-2");
  EXPECT_FALSE(estimator.GetURLRequestRTTEstimate(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
}

// Verifies that the percentiles are correctly computed. All observations have
// the same timestamp. Kbps percentiles must be in decreasing order. RTT
// percentiles must be in increasing order.
TEST(NetworkQualityEstimatorTest, PercentileSameTimestamps) {
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);
  base::TimeTicks now = base::TimeTicks::Now();

  // Network quality should be unavailable when no observations are available.
  base::TimeDelta rtt;
  EXPECT_FALSE(estimator.GetURLRequestRTTEstimate(&rtt));
  int32_t kbps;
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));

  // Insert samples from {1,2,3,..., 100}. First insert odd samples, then even
  // samples. This helps in verifying that the order of samples does not matter.
  for (int i = 1; i <= 99; i += 2) {
    estimator.downstream_throughput_kbps_observations_.AddObservation(
        NetworkQualityEstimator::ThroughputObservation(
            i, now, NetworkQualityEstimator::URL_REQUEST));
    estimator.rtt_observations_.AddObservation(
        NetworkQualityEstimator::RttObservation(
            base::TimeDelta::FromMilliseconds(i), now,
            NetworkQualityEstimator::URL_REQUEST));
    EXPECT_TRUE(estimator.GetURLRequestRTTEstimate(&rtt));
    EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  }

  for (int i = 1; i <= 99; i += 2) {
    // Insert TCP observation which should not be taken into account when
    // computing median RTT at HTTP layer.
    estimator.rtt_observations_.AddObservation(
        NetworkQualityEstimator::RttObservation(
            base::TimeDelta::FromMilliseconds(10000), now,
            NetworkQualityEstimator::TCP));

    // Insert QUIC observation which should not be taken into account when
    // computing median RTT at HTTP layer.
    estimator.rtt_observations_.AddObservation(
        NetworkQualityEstimator::RttObservation(
            base::TimeDelta::FromMilliseconds(10000), now,
            NetworkQualityEstimator::QUIC));
  }

  for (int i = 2; i <= 100; i += 2) {
    estimator.downstream_throughput_kbps_observations_.AddObservation(
        NetworkQualityEstimator::ThroughputObservation(
            i, now, NetworkQualityEstimator::URL_REQUEST));
    estimator.rtt_observations_.AddObservation(
        NetworkQualityEstimator::RttObservation(
            base::TimeDelta::FromMilliseconds(i), now,
            NetworkQualityEstimator::URL_REQUEST));
    EXPECT_TRUE(estimator.GetURLRequestRTTEstimate(&rtt));
    EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  }

  for (int i = 0; i <= 100; ++i) {
    // Checks if the difference between the two integers is less than 1. This is
    // required because computed percentiles may be slightly different from
    // what is expected due to floating point computation errors and integer
    // rounding off errors.
    EXPECT_NEAR(estimator.GetDownlinkThroughputKbpsEstimateInternal(
                    base::TimeTicks(), i),
                100 - i, 1);
    std::vector<NetworkQualityEstimator::ObservationSource>
        disallowed_observation_sources;
    disallowed_observation_sources.push_back(NetworkQualityEstimator::TCP);
    disallowed_observation_sources.push_back(NetworkQualityEstimator::QUIC);
    EXPECT_NEAR(estimator
                    .GetRTTEstimateInternal(disallowed_observation_sources,
                                            base::TimeTicks(), i)
                    .InMilliseconds(),
                i, 1);
  }

  EXPECT_TRUE(estimator.GetURLRequestRTTEstimate(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
}

// Verifies that the percentiles are correctly computed. Observations have
// different timestamps with half the observations being very old and the rest
// of them being very recent. Percentiles should factor in recent observations
// much more heavily than older samples. Kbps percentiles must be in decreasing
// order. RTT percentiles must be in increasing order.
TEST(NetworkQualityEstimatorTest, PercentileDifferentTimestamps) {
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);
  base::TimeTicks now = base::TimeTicks::Now();
  base::TimeTicks very_old = now - base::TimeDelta::FromDays(365);

  // First 50 samples have very old timestamp.
  for (int i = 1; i <= 50; ++i) {
    estimator.downstream_throughput_kbps_observations_.AddObservation(
        NetworkQualityEstimator::ThroughputObservation(
            i, very_old, NetworkQualityEstimator::URL_REQUEST));
    estimator.rtt_observations_.AddObservation(
        NetworkQualityEstimator::RttObservation(
            base::TimeDelta::FromMilliseconds(i), very_old,
            NetworkQualityEstimator::URL_REQUEST));
  }

  // Next 50 (i.e., from 51 to 100) have recent timestamp.
  for (int i = 51; i <= 100; ++i) {
    estimator.downstream_throughput_kbps_observations_.AddObservation(
        NetworkQualityEstimator::ThroughputObservation(
            i, now, NetworkQualityEstimator::URL_REQUEST));

    // Insert TCP observation which should not be taken into account when
    // computing median RTT at HTTP layer.
    estimator.rtt_observations_.AddObservation(
        NetworkQualityEstimator::RttObservation(
            base::TimeDelta::FromMilliseconds(10000), now,
            NetworkQualityEstimator::TCP));

    estimator.rtt_observations_.AddObservation(
        NetworkQualityEstimator::RttObservation(
            base::TimeDelta::FromMilliseconds(i), now,
            NetworkQualityEstimator::URL_REQUEST));
  }

  std::vector<NetworkQualityEstimator::ObservationSource>
      disallowed_observation_sources;
  disallowed_observation_sources.push_back(NetworkQualityEstimator::TCP);
  disallowed_observation_sources.push_back(NetworkQualityEstimator::QUIC);

  // Older samples have very little weight. So, all percentiles are >= 51
  // (lowest value among recent observations).
  for (int i = 1; i < 100; ++i) {
    // Checks if the difference between the two integers is less than 1. This is
    // required because computed percentiles may be slightly different from
    // what is expected due to floating point computation errors and integer
    // rounding off errors.
    EXPECT_NEAR(estimator.GetDownlinkThroughputKbpsEstimateInternal(
                    base::TimeTicks(), i),
                51 + 0.49 * (100 - i), 1);
    EXPECT_NEAR(estimator
                    .GetRTTEstimateInternal(disallowed_observation_sources,
                                            base::TimeTicks(), i)
                    .InMilliseconds(),
                51 + 0.49 * i, 1);
  }
}

// This test notifies NetworkQualityEstimator of received data. Next,
// throughput and RTT percentiles are checked for correctness by doing simple
// verifications.
TEST(NetworkQualityEstimatorTest, ComputedPercentiles) {
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);

  std::vector<NetworkQualityEstimator::ObservationSource>
      disallowed_observation_sources;
  disallowed_observation_sources.push_back(NetworkQualityEstimator::TCP);
  disallowed_observation_sources.push_back(NetworkQualityEstimator::QUIC);

  EXPECT_EQ(NetworkQualityEstimator::InvalidRTT(),
            estimator.GetRTTEstimateInternal(disallowed_observation_sources,
                                             base::TimeTicks(), 100));
  EXPECT_EQ(NetworkQualityEstimator::kInvalidThroughput,
            estimator.GetDownlinkThroughputKbpsEstimateInternal(
                base::TimeTicks(), 100));

  TestDelegate test_delegate;
  TestURLRequestContext context(true);
  context.set_network_quality_estimator(&estimator);
  context.Init();

  // Number of observations are more than the maximum buffer size.
  for (size_t i = 0; i < estimator.kMaximumObservationsBufferSize + 100U; ++i) {
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
  EXPECT_TRUE(estimator.GetURLRequestRTTEstimate(&rtt));
  int32_t kbps;
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));

  EXPECT_EQ(100, kbps);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(1000), rtt);

  // Simulate network change to Wi-Fi.
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-1");

  EXPECT_TRUE(estimator.GetURLRequestRTTEstimate(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  EXPECT_EQ(200, kbps);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(2000), rtt);

  // Peak network quality should not be affected by the network quality
  // estimator field trial.
  EXPECT_EQ(NetworkQualityEstimator::InvalidRTT(),
            estimator.peak_network_quality_.rtt());
  EXPECT_EQ(NetworkQualityEstimator::kInvalidThroughput,
            estimator.peak_network_quality_.downstream_throughput_kbps());

  // Simulate network change to 2G. Only the Kbps default estimate should be
  // available.
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test-2");

  EXPECT_FALSE(estimator.GetURLRequestRTTEstimate(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  EXPECT_EQ(300, kbps);

  // Simulate network change to 3G. Default estimates should be unavailable.
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_3G, "test-3");

  EXPECT_FALSE(estimator.GetURLRequestRTTEstimate(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
}

// Tests that |GetEffectiveConnectionType| returns correct connection type when
// no variation params are specified.
TEST(NetworkQualityEstimatorTest, ObtainThresholdsNone) {
  std::map<std::string, std::string> variation_params;

  TestNetworkQualityEstimator estimator(variation_params);

  const struct {
    int32_t rtt_msec;
    NetworkQualityEstimator::EffectiveConnectionType expected_conn_type;
  } tests[] = {
      {5000, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_BROADBAND},
      {20, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_BROADBAND},
  };

  for (const auto& test : tests) {
    estimator.set_url_rtt(base::TimeDelta::FromMilliseconds(test.rtt_msec));
    EXPECT_EQ(test.expected_conn_type, estimator.GetEffectiveConnectionType());
  }
}

// Tests that |GetEffectiveConnectionType| returns correct connection type when
// only RTT thresholds are specified in the variation params.
TEST(NetworkQualityEstimatorTest, ObtainThresholdsOnlyRTT) {
  std::map<std::string, std::string> variation_params;

  variation_params["Offline.ThresholdMedianURLRTTMsec"] = "4000";
  variation_params["Slow2G.ThresholdMedianURLRTTMsec"] = "2000";
  variation_params["2G.ThresholdMedianURLRTTMsec"] = "1000";
  variation_params["3G.ThresholdMedianURLRTTMsec"] = "500";
  variation_params["4G.ThresholdMedianURLRTTMsec"] = "300";
  variation_params["Broadband.ThresholdMedianURLRTTMsec"] = "100";

  TestNetworkQualityEstimator estimator(variation_params);

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
    estimator.set_url_rtt(base::TimeDelta::FromMilliseconds(test.rtt_msec));
    EXPECT_EQ(test.expected_conn_type, estimator.GetEffectiveConnectionType());
  }
}

// Tests that |GetEffectiveConnectionType| returns correct connection type when
// both RTT and throughput thresholds are specified in the variation params.
TEST(NetworkQualityEstimatorTest, ObtainThresholdsRTTandThroughput) {
  std::map<std::string, std::string> variation_params;

  variation_params["Offline.ThresholdMedianURLRTTMsec"] = "4000";
  variation_params["Slow2G.ThresholdMedianURLRTTMsec"] = "2000";
  variation_params["2G.ThresholdMedianURLRTTMsec"] = "1000";
  variation_params["3G.ThresholdMedianURLRTTMsec"] = "500";
  variation_params["4G.ThresholdMedianURLRTTMsec"] = "300";
  variation_params["Broadband.ThresholdMedianURLRTTMsec"] = "100";

  variation_params["Offline.ThresholdMedianKbps"] = "10";
  variation_params["Slow2G.ThresholdMedianKbps"] = "100";
  variation_params["2G.ThresholdMedianKbps"] = "300";
  variation_params["3G.ThresholdMedianKbps"] = "500";
  variation_params["4G.ThresholdMedianKbps"] = "1000";
  variation_params["Broadband.ThresholdMedianKbps"] = "2000";

  TestNetworkQualityEstimator estimator(variation_params);

  const struct {
    int32_t rtt_msec;
    int32_t downlink_throughput_kbps;
    NetworkQualityEstimator::EffectiveConnectionType expected_conn_type;
  } tests[] = {
      // Set RTT to a very low value to observe the effect of throughput.
      // Throughout is the bottleneck.
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
      // Set throughput to an invalid value.
      {3000, 0, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {700, 0, NetworkQualityEstimator::EFFECTIVE_CONNECTION_TYPE_3G},
  };

  for (const auto& test : tests) {
    estimator.set_url_rtt(base::TimeDelta::FromMilliseconds(test.rtt_msec));
    estimator.set_downlink_throughput_kbps(test.downlink_throughput_kbps);
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
          1, base::TimeTicks::Now(), NetworkQualityEstimator::URL_REQUEST));
  estimator.rtt_observations_.AddObservation(
      NetworkQualityEstimator::RttObservation(
          base::TimeDelta::FromMilliseconds(1000), base::TimeTicks::Now(),
          NetworkQualityEstimator::URL_REQUEST));
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test-1");
  EXPECT_EQ(expected_cache_size, estimator.cached_network_qualities_.size());

  // Entry will be added for (2G, "test1").
  // Also, set the network quality for (2G, "test1") so that it is stored in
  // the cache.
  estimator.downstream_throughput_kbps_observations_.AddObservation(
      NetworkQualityEstimator::ThroughputObservation(
          1, base::TimeTicks::Now(), NetworkQualityEstimator::URL_REQUEST));
  estimator.rtt_observations_.AddObservation(
      NetworkQualityEstimator::RttObservation(
          base::TimeDelta::FromMilliseconds(1000), base::TimeTicks::Now(),
          NetworkQualityEstimator::URL_REQUEST));

  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_3G, "test-1");
  ++expected_cache_size;
  EXPECT_EQ(expected_cache_size, estimator.cached_network_qualities_.size());

  // Entry will be added for (3G, "test1").
  // Also, set the network quality for (3G, "test1") so that it is stored in
  // the cache.
  estimator.downstream_throughput_kbps_observations_.AddObservation(
      NetworkQualityEstimator::ThroughputObservation(
          2, base::TimeTicks::Now(), NetworkQualityEstimator::URL_REQUEST));
  estimator.rtt_observations_.AddObservation(
      NetworkQualityEstimator::RttObservation(
          base::TimeDelta::FromMilliseconds(500), base::TimeTicks::Now(),
          NetworkQualityEstimator::URL_REQUEST));
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
  EXPECT_TRUE(estimator.GetURLRequestRTTEstimate(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  EXPECT_EQ(1, kbps);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(1000), rtt);
  // No new entry should be added for (2G, "test-1") since it already exists
  // in the cache.
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_3G, "test-1");
  EXPECT_EQ(expected_cache_size, estimator.cached_network_qualities_.size());

  // Read the network quality for (3G, "test-1").
  EXPECT_TRUE(estimator.ReadCachedNetworkQualityEstimate());
  EXPECT_TRUE(estimator.GetURLRequestRTTEstimate(&rtt));
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
            2, base::TimeTicks::Now(), NetworkQualityEstimator::URL_REQUEST));
    estimator.rtt_observations_.AddObservation(
        NetworkQualityEstimator::RttObservation(
            base::TimeDelta::FromMilliseconds(500), base::TimeTicks::Now(),
            NetworkQualityEstimator::URL_REQUEST));

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
          2, base::TimeTicks::Now(), NetworkQualityEstimator::URL_REQUEST));
  estimator.rtt_observations_.AddObservation(
      NetworkQualityEstimator::RttObservation(
          base::TimeDelta::FromMilliseconds(500), base::TimeTicks::Now(),
          NetworkQualityEstimator::URL_REQUEST));
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

TEST(NetworkQualityEstimatorTest, TestGetMedianRTTSince) {
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);
  base::TimeTicks now = base::TimeTicks::Now();
  base::TimeTicks old = now - base::TimeDelta::FromMilliseconds(1);
  ASSERT_NE(old, now);

  // First sample has very old timestamp.
  estimator.downstream_throughput_kbps_observations_.AddObservation(
      NetworkQualityEstimator::ThroughputObservation(
          1, old, NetworkQualityEstimator::URL_REQUEST));
  estimator.rtt_observations_.AddObservation(
      NetworkQualityEstimator::RttObservation(
          base::TimeDelta::FromMilliseconds(1), old,
          NetworkQualityEstimator::URL_REQUEST));

  estimator.downstream_throughput_kbps_observations_.AddObservation(
      NetworkQualityEstimator::ThroughputObservation(
          100, now, NetworkQualityEstimator::URL_REQUEST));
  estimator.rtt_observations_.AddObservation(
      NetworkQualityEstimator::RttObservation(
          base::TimeDelta::FromMilliseconds(100), now,
          NetworkQualityEstimator::URL_REQUEST));

  const struct {
    base::TimeTicks start_timestamp;
    bool expect_network_quality_available;
    base::TimeDelta expected_url_request_rtt;
    int32_t expected_downstream_throughput;
  } tests[] = {
      {now + base::TimeDelta::FromSeconds(10), false,
       base::TimeDelta::FromMilliseconds(0), 0},
      {now, true, base::TimeDelta::FromMilliseconds(100), 100},
      {now - base::TimeDelta::FromMicroseconds(500), true,
       base::TimeDelta::FromMilliseconds(100), 100},

  };

  for (const auto& test : tests) {
    base::TimeDelta url_request_rtt;
    int32_t downstream_throughput_kbps;
    EXPECT_EQ(test.expect_network_quality_available,
              estimator.GetRecentURLRequestRTTMedian(test.start_timestamp,
                                                     &url_request_rtt));
    EXPECT_EQ(test.expect_network_quality_available,
              estimator.GetRecentMedianDownlinkThroughputKbps(
                  test.start_timestamp, &downstream_throughput_kbps));

    if (test.expect_network_quality_available) {
      EXPECT_EQ(test.expected_url_request_rtt, url_request_rtt);
      EXPECT_EQ(test.expected_downstream_throughput,
                downstream_throughput_kbps);
    }
  }
}

// An external estimate provider that does not have a valid RTT or throughput
// estimate.
class InvalidExternalEstimateProvider : public ExternalEstimateProvider {
 public:
  InvalidExternalEstimateProvider() : get_rtt_count_(0) {}
  ~InvalidExternalEstimateProvider() override {}

  // ExternalEstimateProvider implementation:
  bool GetRTT(base::TimeDelta* rtt) const override {
    DCHECK(rtt);
    get_rtt_count_++;
    return false;
  }

  // ExternalEstimateProvider implementation:
  bool GetDownstreamThroughputKbps(
      int32_t* downstream_throughput_kbps) const override {
    DCHECK(downstream_throughput_kbps);
    return false;
  }

  // ExternalEstimateProvider implementation:
  bool GetUpstreamThroughputKbps(
      int32_t* upstream_throughput_kbps) const override {
    // NetworkQualityEstimator does not support upstream throughput.
    ADD_FAILURE();
    return false;
  }

  // ExternalEstimateProvider implementation:
  bool GetTimeSinceLastUpdate(
      base::TimeDelta* time_since_last_update) const override {
    *time_since_last_update = base::TimeDelta::FromMilliseconds(1);
    return true;
  }

  // ExternalEstimateProvider implementation:
  void SetUpdatedEstimateDelegate(UpdatedEstimateDelegate* delegate) override {}

  // ExternalEstimateProvider implementation:
  void Update() const override {}

  size_t get_rtt_count() const { return get_rtt_count_; }

 private:
  // Keeps track of number of times different functions were called.
  mutable size_t get_rtt_count_;

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

  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_EQ(1U, invalid_external_estimate_provider->get_rtt_count());
  EXPECT_FALSE(estimator.GetURLRequestRTTEstimate(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  histogram_tester.ExpectTotalCount("NQE.ExternalEstimateProviderStatus", 3);

  histogram_tester.ExpectBucketCount(
      "NQE.ExternalEstimateProviderStatus",
      1 /* EXTERNAL_ESTIMATE_PROVIDER_STATUS_AVAILABLE */, 1);
  histogram_tester.ExpectBucketCount(
      "NQE.ExternalEstimateProviderStatus",
      2 /* EXTERNAL_ESTIMATE_PROVIDER_STATUS_QUERIED */, 1);
  histogram_tester.ExpectBucketCount(
      "NQE.ExternalEstimateProviderStatus",
      3 /* EXTERNAL_ESTIMATE_PROVIDER_STATUS_QUERY_SUCCESSFUL */, 1);
  histogram_tester.ExpectTotalCount("NQE.ExternalEstimateProvider.RTT", 0);
  histogram_tester.ExpectTotalCount(
      "NQE.ExternalEstimateProvider.DownlinkBandwidth", 0);
}

class TestExternalEstimateProvider : public ExternalEstimateProvider {
 public:
  TestExternalEstimateProvider(base::TimeDelta rtt,
                               int32_t downstream_throughput_kbps)
      : rtt_(rtt),
        downstream_throughput_kbps_(downstream_throughput_kbps),
        time_since_last_update_(base::TimeDelta::FromSeconds(1)),
        get_time_since_last_update_count_(0),
        get_rtt_count_(0),
        get_downstream_throughput_kbps_count_(0),
        update_count_(0) {}
  ~TestExternalEstimateProvider() override {}

  // ExternalEstimateProvider implementation:
  bool GetRTT(base::TimeDelta* rtt) const override {
    *rtt = rtt_;
    get_rtt_count_++;
    return true;
  }

  // ExternalEstimateProvider implementation:
  bool GetDownstreamThroughputKbps(
      int32_t* downstream_throughput_kbps) const override {
    *downstream_throughput_kbps = downstream_throughput_kbps_;
    get_downstream_throughput_kbps_count_++;
    return true;
  }

  // ExternalEstimateProvider implementation:
  bool GetUpstreamThroughputKbps(
      int32_t* upstream_throughput_kbps) const override {
    // NetworkQualityEstimator does not support upstream throughput.
    ADD_FAILURE();
    return false;
  }

  // ExternalEstimateProvider implementation:
  bool GetTimeSinceLastUpdate(
      base::TimeDelta* time_since_last_update) const override {
    *time_since_last_update = time_since_last_update_;
    get_time_since_last_update_count_++;
    return true;
  }

  // ExternalEstimateProvider implementation:
  void SetUpdatedEstimateDelegate(UpdatedEstimateDelegate* delegate) override {}

  // ExternalEstimateProvider implementation:
  void Update() const override { update_count_++; }

  void set_time_since_last_update(base::TimeDelta time_since_last_update) {
    time_since_last_update_ = time_since_last_update;
  }

  size_t get_time_since_last_update_count() const {
    return get_time_since_last_update_count_;
  }
  size_t get_rtt_count() const { return get_rtt_count_; }
  size_t get_downstream_throughput_kbps_count() const {
    return get_downstream_throughput_kbps_count_;
  }
  size_t update_count() const { return update_count_; }

 private:
  // RTT and downstream throughput estimates.
  const base::TimeDelta rtt_;
  const int32_t downstream_throughput_kbps_;

  base::TimeDelta time_since_last_update_;

  // Keeps track of number of times different functions were called.
  mutable size_t get_time_since_last_update_count_;
  mutable size_t get_rtt_count_;
  mutable size_t get_downstream_throughput_kbps_count_;
  mutable size_t update_count_;

  DISALLOW_COPY_AND_ASSIGN(TestExternalEstimateProvider);
};

// Tests if the external estimate provider is called in the constructor and
// on network change notification.
TEST(NetworkQualityEstimatorTest, TestExternalEstimateProvider) {
  base::HistogramTester histogram_tester;
  TestExternalEstimateProvider* test_external_estimate_provider =
      new TestExternalEstimateProvider(base::TimeDelta::FromMilliseconds(1),
                                       100);
  std::unique_ptr<ExternalEstimateProvider> external_estimate_provider(
      test_external_estimate_provider);
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params,
                                        std::move(external_estimate_provider));

  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_TRUE(estimator.GetURLRequestRTTEstimate(&rtt));
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
      3 /* EXTERNAL_ESTIMATE_PROVIDER_STATUS_QUERY_SUCCESSFUL */, 1);
  histogram_tester.ExpectBucketCount(
      "NQE.ExternalEstimateProviderStatus",
      5 /* EXTERNAL_ESTIMATE_PROVIDER_STATUS_RTT_AVAILABLE */, 1);
  histogram_tester.ExpectBucketCount(
      "NQE.ExternalEstimateProviderStatus",
      6 /* EXTERNAL_ESTIMATE_PROVIDER_STATUS_DOWNLINK_BANDWIDTH_AVAILABLE */,
      1);
  histogram_tester.ExpectTotalCount("NQE.ExternalEstimateProvider.RTT", 1);
  histogram_tester.ExpectBucketCount("NQE.ExternalEstimateProvider.RTT", 1, 1);

  histogram_tester.ExpectTotalCount(
      "NQE.ExternalEstimateProvider.DownlinkBandwidth", 1);
  histogram_tester.ExpectBucketCount(
      "NQE.ExternalEstimateProvider.DownlinkBandwidth", 100, 1);

  EXPECT_EQ(
      1U, test_external_estimate_provider->get_time_since_last_update_count());
  EXPECT_EQ(1U, test_external_estimate_provider->get_rtt_count());
  EXPECT_EQ(
      1U,
      test_external_estimate_provider->get_downstream_throughput_kbps_count());

  // Change network type to WiFi. Number of queries to External estimate
  // provider must increment.
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-1");
  EXPECT_TRUE(estimator.GetURLRequestRTTEstimate(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  EXPECT_EQ(
      2U, test_external_estimate_provider->get_time_since_last_update_count());
  EXPECT_EQ(2U, test_external_estimate_provider->get_rtt_count());
  EXPECT_EQ(
      2U,
      test_external_estimate_provider->get_downstream_throughput_kbps_count());

  // Change network type to 2G. Number of queries to External estimate provider
  // must increment.
  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test-1");
  EXPECT_EQ(
      3U, test_external_estimate_provider->get_time_since_last_update_count());
  EXPECT_EQ(3U, test_external_estimate_provider->get_rtt_count());
  EXPECT_EQ(
      3U,
      test_external_estimate_provider->get_downstream_throughput_kbps_count());

  // Set the external estimate as old. Network Quality estimator should request
  // an update on connection type change.
  EXPECT_EQ(0U, test_external_estimate_provider->update_count());
  test_external_estimate_provider->set_time_since_last_update(
      base::TimeDelta::Max());

  estimator.SimulateNetworkChangeTo(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test-2");
  EXPECT_EQ(
      4U, test_external_estimate_provider->get_time_since_last_update_count());
  EXPECT_EQ(3U, test_external_estimate_provider->get_rtt_count());
  EXPECT_EQ(
      3U,
      test_external_estimate_provider->get_downstream_throughput_kbps_count());
  EXPECT_EQ(1U, test_external_estimate_provider->update_count());

  // Estimates are unavailable because external estimate provider never
  // notifies network quality estimator of the updated estimates.
  EXPECT_FALSE(estimator.GetURLRequestRTTEstimate(&rtt));
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

  base::TimeDelta rtt;
  // Estimate provided by network quality estimator should match the estimate
  // provided by external estimate provider.
  EXPECT_TRUE(estimator.GetURLRequestRTTEstimate(&rtt));
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

  EXPECT_TRUE(estimator.GetURLRequestRTTEstimate(&rtt));
  EXPECT_NE(external_estimate_provider_rtt, rtt);

  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&kbps));
  EXPECT_NE(external_estimate_provider_downstream_throughput, kbps);
}

TEST(NetworkQualityEstimatorTest, TestObservers) {
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
  EXPECT_TRUE(estimator.GetURLRequestRTTEstimate(&rtt));

  int32_t throughput;
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbpsEstimate(&throughput));

  EXPECT_EQ(2U, rtt_observer.observations().size());
  EXPECT_EQ(2U, throughput_observer.observations().size());
  for (const auto& observation : rtt_observer.observations()) {
    EXPECT_LE(0, observation.rtt_ms);
    EXPECT_LE(0, (observation.timestamp - then).InMilliseconds());
    EXPECT_EQ(NetworkQualityEstimator::URL_REQUEST, observation.source);
  }
  for (const auto& observation : throughput_observer.observations()) {
    EXPECT_LE(0, observation.throughput_kbps);
    EXPECT_LE(0, (observation.timestamp - then).InMilliseconds());
    EXPECT_EQ(NetworkQualityEstimator::URL_REQUEST, observation.source);
  }

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
  EXPECT_FALSE(estimator.GetURLRequestRTTEstimate(&rtt));

  // Send two requests. Verify that the completion of each request generates at
  // least one TCP RTT observation.
  for (size_t i = 0; i < 2; ++i) {
    size_t before_count_tcp_rtt_observations = 0;
    for (const auto& observation : rtt_observer.observations()) {
      if (observation.source == NetworkQualityEstimator::TCP)
        ++before_count_tcp_rtt_observations;
    }

    std::unique_ptr<URLRequest> request(context.CreateRequest(
        estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
    request->Start();
    base::RunLoop().Run();

    size_t after_count_tcp_rtt_observations = 0;
    for (const auto& observation : rtt_observer.observations()) {
      if (observation.source == NetworkQualityEstimator::TCP)
        ++after_count_tcp_rtt_observations;
    }
    // At least one notification should be received per socket performance
    // watcher.
    EXPECT_LE(1U, after_count_tcp_rtt_observations -
                      before_count_tcp_rtt_observations)
        << i;
  }
  EXPECT_TRUE(estimator.GetURLRequestRTTEstimate(&rtt));
}

}  // namespace net

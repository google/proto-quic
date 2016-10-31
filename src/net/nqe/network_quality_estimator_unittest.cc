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
#include "net/nqe/effective_connection_type.h"
#include "net/nqe/external_estimate_provider.h"
#include "net/nqe/network_quality_estimator_test_util.h"
#include "net/nqe/network_quality_observation.h"
#include "net/nqe/network_quality_observation_source.h"
#include "net/nqe/observation_buffer.h"
#include "net/socket/socket_performance_watcher.h"
#include "net/socket/socket_performance_watcher_factory.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

namespace {

class TestEffectiveConnectionTypeObserver
    : public NetworkQualityEstimator::EffectiveConnectionTypeObserver {
 public:
  std::vector<EffectiveConnectionType>& effective_connection_types() {
    return effective_connection_types_;
  }

  // EffectiveConnectionTypeObserver implementation:
  void OnEffectiveConnectionTypeChanged(EffectiveConnectionType type) override {
    effective_connection_types_.push_back(type);
  }

 private:
  std::vector<EffectiveConnectionType> effective_connection_types_;
};

class TestRTTAndThroughputEstimatesObserver
    : public NetworkQualityEstimator::RTTAndThroughputEstimatesObserver {
 public:
  TestRTTAndThroughputEstimatesObserver()
      : http_rtt_(nqe::internal::InvalidRTT()),
        transport_rtt_(nqe::internal::InvalidRTT()),
        downstream_throughput_kbps_(nqe::internal::kInvalidThroughput),
        notifications_received_(0) {}

  // RTTAndThroughputEstimatesObserver implementation:
  void OnRTTOrThroughputEstimatesComputed(
      base::TimeDelta http_rtt,
      base::TimeDelta transport_rtt,
      int32_t downstream_throughput_kbps) override {
    http_rtt_ = http_rtt;
    transport_rtt_ = transport_rtt;
    downstream_throughput_kbps_ = downstream_throughput_kbps;
    notifications_received_++;
  }

  int notifications_received() const { return notifications_received_; }

  base::TimeDelta http_rtt() const { return http_rtt_; }
  base::TimeDelta transport_rtt() const { return transport_rtt_; }
  int32_t downstream_throughput_kbps() const {
    return downstream_throughput_kbps_;
  }

 private:
  base::TimeDelta http_rtt_;
  base::TimeDelta transport_rtt_;
  int32_t downstream_throughput_kbps_;
  int notifications_received_;
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

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN, "test");
  histogram_tester.ExpectUniqueSample("NQE.CachedNetworkQualityAvailable",
                                      false, 1);

  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_FALSE(estimator.GetHttpRTT(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbps(&kbps));

  TestDelegate test_delegate;
  TestURLRequestContext context(true);
  context.set_network_quality_estimator(&estimator);
  context.Init();

  std::unique_ptr<URLRequest> request(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request->Start();
  base::RunLoop().Run();

  // Both RTT and downstream throughput should be updated.
  EXPECT_TRUE(estimator.GetHttpRTT(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbps(&kbps));
  EXPECT_FALSE(estimator.GetTransportRTT(&rtt));

  // Check UMA histograms.
  histogram_tester.ExpectTotalCount("NQE.PeakKbps.Unknown", 0);
  histogram_tester.ExpectTotalCount("NQE.FastestRTT.Unknown", 0);
  histogram_tester.ExpectUniqueSample(
      "NQE.MainFrame.EffectiveConnectionType",
      EffectiveConnectionType::EFFECTIVE_CONNECTION_TYPE_UNKNOWN, 1);
  histogram_tester.ExpectUniqueSample(
      "NQE.MainFrame.EffectiveConnectionType.Unknown",
      EffectiveConnectionType::EFFECTIVE_CONNECTION_TYPE_UNKNOWN, 1);

  std::unique_ptr<URLRequest> request2(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request2->SetLoadFlags(request2->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request2->Start();
  base::RunLoop().Run();
  histogram_tester.ExpectTotalCount("NQE.MainFrame.EffectiveConnectionType", 2);
  histogram_tester.ExpectTotalCount(
      "NQE.MainFrame.EffectiveConnectionType.Unknown", 2);

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-1");
  histogram_tester.ExpectUniqueSample("NQE.CachedNetworkQualityAvailable",
                                      false, 2);
  histogram_tester.ExpectTotalCount("NQE.PeakKbps.Unknown", 1);
  histogram_tester.ExpectTotalCount("NQE.FastestRTT.Unknown", 1);

  histogram_tester.ExpectTotalCount("NQE.RatioMedianRTT.WiFi", 0);

  histogram_tester.ExpectTotalCount("NQE.RTT.Percentile0.Unknown", 1);
  histogram_tester.ExpectTotalCount("NQE.RTT.Percentile10.Unknown", 1);
  histogram_tester.ExpectTotalCount("NQE.RTT.Percentile50.Unknown", 1);
  histogram_tester.ExpectTotalCount("NQE.RTT.Percentile90.Unknown", 1);
  histogram_tester.ExpectTotalCount("NQE.RTT.Percentile100.Unknown", 1);

  histogram_tester.ExpectTotalCount("NQE.TransportRTT.Percentile50.Unknown", 0);

  EXPECT_FALSE(estimator.GetHttpRTT(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbps(&kbps));

  // Verify that metrics are logged correctly on main-frame requests.
  histogram_tester.ExpectTotalCount("NQE.MainFrame.RTT.Percentile50", 1);
  histogram_tester.ExpectTotalCount("NQE.MainFrame.RTT.Percentile50.Unknown",
                                    1);
  histogram_tester.ExpectTotalCount("NQE.MainFrame.TransportRTT.Percentile50",
                                    0);
  histogram_tester.ExpectTotalCount(
      "NQE.MainFrame.TransportRTT.Percentile50.Unknown", 0);
  histogram_tester.ExpectTotalCount("NQE.MainFrame.Kbps.Percentile50", 1);
  histogram_tester.ExpectTotalCount("NQE.MainFrame.Kbps.Percentile50.Unknown",
                                    1);

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, std::string());
  histogram_tester.ExpectUniqueSample("NQE.CachedNetworkQualityAvailable",
                                      false, 3);
  histogram_tester.ExpectTotalCount("NQE.PeakKbps.Unknown", 1);
  histogram_tester.ExpectTotalCount("NQE.FastestRTT.Unknown", 1);

  EXPECT_FALSE(estimator.GetHttpRTT(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbps(&kbps));

  std::unique_ptr<URLRequest> request3(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request3->SetLoadFlags(request2->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request3->Start();
  base::RunLoop().Run();
  histogram_tester.ExpectUniqueSample(
      "NQE.MainFrame.EffectiveConnectionType.WiFi",
      EffectiveConnectionType::EFFECTIVE_CONNECTION_TYPE_UNKNOWN, 1);
  histogram_tester.ExpectTotalCount("NQE.MainFrame.EffectiveConnectionType", 3);

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN, "test");
  histogram_tester.ExpectBucketCount("NQE.CachedNetworkQualityAvailable", false,
                                     3);
  histogram_tester.ExpectBucketCount("NQE.CachedNetworkQualityAvailable", true,
                                     1);
}

// Tests that the network quality estimator writes and reads network quality
// from the cache store correctly.
TEST(NetworkQualityEstimatorTest, Caching) {
  base::HistogramTester histogram_tester;
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test");
  histogram_tester.ExpectUniqueSample("NQE.CachedNetworkQualityAvailable",
                                      false, 1);

  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_FALSE(estimator.GetHttpRTT(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbps(&kbps));

  TestDelegate test_delegate;
  TestURLRequestContext context(true);
  context.set_network_quality_estimator(&estimator);
  context.Init();

  // Start two requests so that the network quality is added to cache store at
  // the beginning of the second request from the network traffic observed from
  // the first request.
  for (size_t i = 0; i < 2; ++i) {
    std::unique_ptr<URLRequest> request(context.CreateRequest(
        estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
    request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
    request->Start();
    base::RunLoop().Run();
  }

  base::RunLoop().RunUntilIdle();

  // Both RTT and downstream throughput should be updated.
  EXPECT_TRUE(estimator.GetHttpRTT(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbps(&kbps));
  EXPECT_NE(EFFECTIVE_CONNECTION_TYPE_UNKNOWN,
            estimator.GetEffectiveConnectionType());
  EXPECT_FALSE(estimator.GetTransportRTT(&rtt));

  histogram_tester.ExpectBucketCount("NQE.CachedNetworkQualityAvailable", false,
                                     1);

  // Add the observers before changing the network type.
  TestEffectiveConnectionTypeObserver observer;
  estimator.AddEffectiveConnectionTypeObserver(&observer);
  TestRTTObserver rtt_observer;
  estimator.AddRTTObserver(&rtt_observer);
  TestThroughputObserver throughput_observer;
  estimator.AddThroughputObserver(&throughput_observer);

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test");
  histogram_tester.ExpectBucketCount("NQE.CachedNetworkQualityAvailable", true,
                                     1);
  histogram_tester.ExpectTotalCount("NQE.CachedNetworkQualityAvailable", 2);
  base::RunLoop().RunUntilIdle();

  // Verify that the cached network quality was read, and observers were
  // notified.
  EXPECT_EQ(1U, observer.effective_connection_types().size());
  EXPECT_EQ(1U, rtt_observer.observations().size());
  EXPECT_EQ(1U, throughput_observer.observations().size());
}

TEST(NetworkQualityEstimatorTest, StoreObservations) {
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);

  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_FALSE(estimator.GetHttpRTT(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbps(&kbps));

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
    EXPECT_TRUE(estimator.GetHttpRTT(&rtt));
    EXPECT_TRUE(estimator.GetDownlinkThroughputKbps(&kbps));
  }

  // Verify that the stored observations are cleared on network change.
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-2");
  EXPECT_FALSE(estimator.GetHttpRTT(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbps(&kbps));
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
  EXPECT_TRUE(estimator.GetHttpRTT(&rtt));
  int32_t kbps;
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbps(&kbps));

  EXPECT_EQ(100, kbps);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(1000), rtt);

  EXPECT_FALSE(estimator.GetTransportRTT(&rtt));

  // Simulate network change to Wi-Fi.
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-1");

  EXPECT_TRUE(estimator.GetHttpRTT(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbps(&kbps));
  EXPECT_EQ(200, kbps);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(2000), rtt);
  EXPECT_FALSE(estimator.GetTransportRTT(&rtt));

  // Peak network quality should not be affected by the network quality
  // estimator field trial.
  EXPECT_EQ(nqe::internal::InvalidRTT(),
            estimator.peak_network_quality_.http_rtt());
  EXPECT_EQ(nqe::internal::kInvalidThroughput,
            estimator.peak_network_quality_.downstream_throughput_kbps());

  // Simulate network change to 2G. Only the Kbps default estimate should be
  // available.
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test-2");

  EXPECT_FALSE(estimator.GetHttpRTT(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbps(&kbps));
  EXPECT_EQ(300, kbps);

  // Simulate network change to 3G. Default estimates should be unavailable.
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_3G, "test-3");

  EXPECT_FALSE(estimator.GetHttpRTT(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbps(&kbps));
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
      {true, "TransportRTTOrDownstreamThroughput",
       NetworkQualityEstimator::EffectiveConnectionTypeAlgorithm::
           TRANSPORT_RTT_OR_DOWNSTREAM_THROUGHOUT},
  };

  for (const auto& test : tests) {
    std::map<std::string, std::string> variation_params;
    if (test.set_variation_param)
      variation_params["effective_connection_type_algorithm"] = test.algorithm;

    TestNetworkQualityEstimator estimator(variation_params);
    EXPECT_EQ(test.expected_algorithm,
              estimator.effective_connection_type_algorithm_)
        << test.algorithm;

    // Make sure no two values are same in the map.
    typedef std::map<std::string,
                     NetworkQualityEstimator::EffectiveConnectionTypeAlgorithm>
        Algorithms;

    for (Algorithms::const_iterator it_first =
             estimator.algorithm_name_to_enum_.begin();
         it_first != estimator.algorithm_name_to_enum_.end(); ++it_first) {
      for (Algorithms::const_iterator it_second =
               estimator.algorithm_name_to_enum_.begin();
           it_second != estimator.algorithm_name_to_enum_.end(); ++it_second) {
        if (it_first != it_second) {
          DCHECK_NE(it_first->second, it_second->second);
        }
      }
    }
  }
}

// Tests that |GetEffectiveConnectionType| returns
// EFFECTIVE_CONNECTION_TYPE_OFFLINE when the device is currently offline.
TEST(NetworkQualityEstimatorTest, Offline) {
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);

  const struct {
    NetworkChangeNotifier::ConnectionType connection_type;
    EffectiveConnectionType expected_connection_type;
  } tests[] = {
      {NetworkChangeNotifier::CONNECTION_2G, EFFECTIVE_CONNECTION_TYPE_UNKNOWN},
      {NetworkChangeNotifier::CONNECTION_NONE,
       EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {NetworkChangeNotifier::CONNECTION_3G, EFFECTIVE_CONNECTION_TYPE_UNKNOWN},
  };

  for (const auto& test : tests) {
    estimator.SimulateNetworkChange(test.connection_type, "test");
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

  TestNetworkQualityEstimator estimator(variation_params);

  // Simulate the connection type as Wi-Fi so that GetEffectiveConnectionType
  // does not return Offline if the device is offline.
  estimator.SimulateNetworkChange(NetworkChangeNotifier::CONNECTION_WIFI,
                                  "test");

  const struct {
    int32_t rtt_msec;
    EffectiveConnectionType expected_conn_type;
  } tests[] = {
      {5000, EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {4000, EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {3000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {2000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {1500, EFFECTIVE_CONNECTION_TYPE_2G},
      {1000, EFFECTIVE_CONNECTION_TYPE_2G},
      {700, EFFECTIVE_CONNECTION_TYPE_3G},
      {500, EFFECTIVE_CONNECTION_TYPE_3G},
      {400, EFFECTIVE_CONNECTION_TYPE_4G},
      {300, EFFECTIVE_CONNECTION_TYPE_4G},
      {200, EFFECTIVE_CONNECTION_TYPE_4G},
      {100, EFFECTIVE_CONNECTION_TYPE_4G},
      {20, EFFECTIVE_CONNECTION_TYPE_4G},
  };

  for (const auto& test : tests) {
    estimator.set_http_rtt(base::TimeDelta::FromMilliseconds(test.rtt_msec));
    estimator.set_recent_http_rtt(
        base::TimeDelta::FromMilliseconds(test.rtt_msec));
    estimator.set_downlink_throughput_kbps(INT32_MAX);
    estimator.set_recent_downlink_throughput_kbps(INT32_MAX);
    // Run one main frame request to force recomputation of effective connection
    // type.
    estimator.RunOneRequest();
    EXPECT_EQ(test.expected_conn_type, estimator.GetEffectiveConnectionType());
  }
}

// Tests that default transport RTT thresholds for different effective
// connection types are correctly set.
TEST(NetworkQualityEstimatorTest, DefaultTransportRTTBasedThresholds) {
  const struct {
    bool override_defaults_using_variation_params;
    int32_t transport_rtt_msec;
    EffectiveConnectionType expected_conn_type;
  } tests[] = {
      // When the variation params do not override connection thresholds,
      // default values should be used.
      {false, 5000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {false, 4000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {false, 3000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {false, 2000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {false, 1500, EFFECTIVE_CONNECTION_TYPE_2G},
      {false, 1000, EFFECTIVE_CONNECTION_TYPE_3G},
      {false, 100, EFFECTIVE_CONNECTION_TYPE_4G},
      {false, 20, EFFECTIVE_CONNECTION_TYPE_4G},
      // Override default thresholds using variation params.
      {true, 5000, EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {true, 4000, EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {true, 3000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {true, 2000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {true, 1500, EFFECTIVE_CONNECTION_TYPE_2G},
      {true, 1000, EFFECTIVE_CONNECTION_TYPE_2G},
      {true, 20, EFFECTIVE_CONNECTION_TYPE_4G},
  };

  for (const auto& test : tests) {
    std::map<std::string, std::string> variation_params;
    variation_params["effective_connection_type_algorithm"] =
        "TransportRTTOrDownstreamThroughput";
    if (test.override_defaults_using_variation_params) {
      variation_params["Offline.ThresholdMedianTransportRTTMsec"] = "4000";
      variation_params["Slow2G.ThresholdMedianTransportRTTMsec"] = "2000";
      variation_params["2G.ThresholdMedianTransportRTTMsec"] = "1000";
    }

    TestNetworkQualityEstimator estimator(variation_params);

    // Simulate the connection type as Wi-Fi so that GetEffectiveConnectionType
    // does not return Offline if the device is offline.
    estimator.SimulateNetworkChange(NetworkChangeNotifier::CONNECTION_WIFI,
                                    "test");

    estimator.set_transport_rtt(
        base::TimeDelta::FromMilliseconds(test.transport_rtt_msec));
    estimator.set_recent_transport_rtt(
        base::TimeDelta::FromMilliseconds(test.transport_rtt_msec));
    estimator.set_downlink_throughput_kbps(INT32_MAX);
    estimator.set_recent_downlink_throughput_kbps(INT32_MAX);
    // Run one main frame request to force recomputation of effective connection
    // type.
    estimator.RunOneRequest();
    EXPECT_EQ(test.expected_conn_type, estimator.GetEffectiveConnectionType());
  }
}

// Tests that default HTTP RTT thresholds for different effective
// connection types are correctly set.
TEST(NetworkQualityEstimatorTest, DefaultHttpRTTBasedThresholds) {
  const struct {
    bool override_defaults_using_variation_params;
    int32_t http_rtt_msec;
    EffectiveConnectionType expected_conn_type;
  } tests[] = {
      // When the variation params do not override connection thresholds,
      // default values should be used.
      {false, 5000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {false, 4000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {false, 3000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {false, 2000, EFFECTIVE_CONNECTION_TYPE_2G},
      {false, 1500, EFFECTIVE_CONNECTION_TYPE_2G},
      {false, 1000, EFFECTIVE_CONNECTION_TYPE_3G},
      {false, 100, EFFECTIVE_CONNECTION_TYPE_4G},
      {false, 20, EFFECTIVE_CONNECTION_TYPE_4G},
      // Override default thresholds using variation params.
      {true, 5000, EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {true, 4000, EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {true, 3000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {true, 2000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {true, 1500, EFFECTIVE_CONNECTION_TYPE_2G},
      {true, 1000, EFFECTIVE_CONNECTION_TYPE_2G},
      {true, 20, EFFECTIVE_CONNECTION_TYPE_4G},
  };

  for (const auto& test : tests) {
    std::map<std::string, std::string> variation_params;
    if (test.override_defaults_using_variation_params) {
      variation_params["Offline.ThresholdMedianHttpRTTMsec"] = "4000";
      variation_params["Slow2G.ThresholdMedianHttpRTTMsec"] = "2000";
      variation_params["2G.ThresholdMedianHttpRTTMsec"] = "1000";
    }

    TestNetworkQualityEstimator estimator(variation_params);

    // Simulate the connection type as Wi-Fi so that GetEffectiveConnectionType
    // does not return Offline if the device is offline.
    estimator.SimulateNetworkChange(NetworkChangeNotifier::CONNECTION_WIFI,
                                    "test");

    estimator.set_http_rtt(
        base::TimeDelta::FromMilliseconds(test.http_rtt_msec));
    estimator.set_recent_http_rtt(
        base::TimeDelta::FromMilliseconds(test.http_rtt_msec));
    estimator.set_downlink_throughput_kbps(INT32_MAX);
    estimator.set_recent_downlink_throughput_kbps(INT32_MAX);
    // Run one main frame request to force recomputation of effective connection
    // type.
    estimator.RunOneRequest();
    EXPECT_EQ(test.expected_conn_type, estimator.GetEffectiveConnectionType());
  }
}

// Tests that |GetEffectiveConnectionType| returns correct connection type when
// only transport RTT thresholds are specified in the variation params.
TEST(NetworkQualityEstimatorTest, ObtainThresholdsOnlyTransportRTT) {
  std::map<std::string, std::string> variation_params;
  variation_params["effective_connection_type_algorithm"] =
      "TransportRTTOrDownstreamThroughput";

  variation_params["Offline.ThresholdMedianTransportRTTMsec"] = "4000";
  variation_params["Slow2G.ThresholdMedianTransportRTTMsec"] = "2000";
  variation_params["2G.ThresholdMedianTransportRTTMsec"] = "1000";
  variation_params["3G.ThresholdMedianTransportRTTMsec"] = "500";
  variation_params["4G.ThresholdMedianTransportRTTMsec"] = "300";

  TestNetworkQualityEstimator estimator(variation_params);

  // Simulate the connection type as Wi-Fi so that GetEffectiveConnectionType
  // does not return Offline if the device is offline.
  estimator.SimulateNetworkChange(NetworkChangeNotifier::CONNECTION_WIFI,
                                  "test");

  const struct {
    int32_t transport_rtt_msec;
    EffectiveConnectionType expected_conn_type;
  } tests[] = {
      {5000, EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {4000, EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {3000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {2000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {1500, EFFECTIVE_CONNECTION_TYPE_2G},
      {1000, EFFECTIVE_CONNECTION_TYPE_2G},
      {700, EFFECTIVE_CONNECTION_TYPE_3G},
      {500, EFFECTIVE_CONNECTION_TYPE_3G},
      {400, EFFECTIVE_CONNECTION_TYPE_4G},
      {300, EFFECTIVE_CONNECTION_TYPE_4G},
      {200, EFFECTIVE_CONNECTION_TYPE_4G},
      {100, EFFECTIVE_CONNECTION_TYPE_4G},
      {20, EFFECTIVE_CONNECTION_TYPE_4G},
  };

  for (const auto& test : tests) {
    estimator.set_transport_rtt(
        base::TimeDelta::FromMilliseconds(test.transport_rtt_msec));
    estimator.set_recent_transport_rtt(
        base::TimeDelta::FromMilliseconds(test.transport_rtt_msec));
    estimator.set_downlink_throughput_kbps(INT32_MAX);
    estimator.set_recent_downlink_throughput_kbps(INT32_MAX);
    // Run one main frame request to force recomputation of effective connection
    // type.
    estimator.RunOneRequest();
    EXPECT_EQ(test.expected_conn_type, estimator.GetEffectiveConnectionType());
  }
}

// Tests that |GetEffectiveConnectionType| returns correct connection type when
// both HTTP RTT and throughput thresholds are specified in the variation
// params.
TEST(NetworkQualityEstimatorTest, ObtainThresholdsHttpRTTandThroughput) {
  std::map<std::string, std::string> variation_params;

  variation_params["Offline.ThresholdMedianHttpRTTMsec"] = "4000";
  variation_params["Slow2G.ThresholdMedianHttpRTTMsec"] = "2000";
  variation_params["2G.ThresholdMedianHttpRTTMsec"] = "1000";
  variation_params["3G.ThresholdMedianHttpRTTMsec"] = "500";
  variation_params["4G.ThresholdMedianHttpRTTMsec"] = "300";

  variation_params["Offline.ThresholdMedianKbps"] = "10";
  variation_params["Slow2G.ThresholdMedianKbps"] = "100";
  variation_params["2G.ThresholdMedianKbps"] = "300";
  variation_params["3G.ThresholdMedianKbps"] = "500";
  variation_params["4G.ThresholdMedianKbps"] = "1000";

  TestNetworkQualityEstimator estimator(variation_params);

  // Simulate the connection type as Wi-Fi so that GetEffectiveConnectionType
  // does not return Offline if the device is offline.
  estimator.SimulateNetworkChange(NetworkChangeNotifier::CONNECTION_WIFI,
                                  "test");

  const struct {
    int32_t rtt_msec;
    int32_t downlink_throughput_kbps;
    EffectiveConnectionType expected_conn_type;
  } tests[] = {
      // Set RTT to a very low value to observe the effect of throughput.
      // Throughput is the bottleneck.
      {1, 5, EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {1, 10, EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {1, 50, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {1, 100, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {1, 150, EFFECTIVE_CONNECTION_TYPE_2G},
      {1, 300, EFFECTIVE_CONNECTION_TYPE_2G},
      {1, 400, EFFECTIVE_CONNECTION_TYPE_3G},
      {1, 500, EFFECTIVE_CONNECTION_TYPE_3G},
      {1, 700, EFFECTIVE_CONNECTION_TYPE_4G},
      {1, 1000, EFFECTIVE_CONNECTION_TYPE_4G},
      {1, 1500, EFFECTIVE_CONNECTION_TYPE_4G},
      {1, 2500, EFFECTIVE_CONNECTION_TYPE_4G},
      // Set both RTT and throughput. RTT is the bottleneck.
      {3000, 25000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {700, 25000, EFFECTIVE_CONNECTION_TYPE_3G},
  };

  for (const auto& test : tests) {
    estimator.set_http_rtt(base::TimeDelta::FromMilliseconds(test.rtt_msec));
    estimator.set_recent_http_rtt(
        base::TimeDelta::FromMilliseconds(test.rtt_msec));
    estimator.set_downlink_throughput_kbps(test.downlink_throughput_kbps);
    estimator.set_recent_downlink_throughput_kbps(
        test.downlink_throughput_kbps);
    // Run one main frame request to force recomputation of effective connection
    // type.
    estimator.RunOneRequest();
    EXPECT_EQ(test.expected_conn_type, estimator.GetEffectiveConnectionType());
  }
}

// Tests that |GetEffectiveConnectionType| returns correct connection type when
// both transport RTT and throughput thresholds are specified in the variation
// params.
TEST(NetworkQualityEstimatorTest, ObtainThresholdsTransportRTTandThroughput) {
  std::map<std::string, std::string> variation_params;
  variation_params["effective_connection_type_algorithm"] =
      "TransportRTTOrDownstreamThroughput";

  variation_params["Offline.ThresholdMedianTransportRTTMsec"] = "4000";
  variation_params["Slow2G.ThresholdMedianTransportRTTMsec"] = "2000";
  variation_params["2G.ThresholdMedianTransportRTTMsec"] = "1000";
  variation_params["3G.ThresholdMedianTransportRTTMsec"] = "500";
  variation_params["4G.ThresholdMedianTransportRTTMsec"] = "300";

  variation_params["Offline.ThresholdMedianKbps"] = "10";
  variation_params["Slow2G.ThresholdMedianKbps"] = "100";
  variation_params["2G.ThresholdMedianKbps"] = "300";
  variation_params["3G.ThresholdMedianKbps"] = "500";
  variation_params["4G.ThresholdMedianKbps"] = "1000";

  TestNetworkQualityEstimator estimator(variation_params);

  // Simulate the connection type as Wi-Fi so that GetEffectiveConnectionType
  // does not return Offline if the device is offline.
  estimator.SimulateNetworkChange(NetworkChangeNotifier::CONNECTION_WIFI,
                                  "test");

  const struct {
    int32_t transport_rtt_msec;
    int32_t downlink_throughput_kbps;
    EffectiveConnectionType expected_conn_type;
  } tests[] = {
      // Set RTT to a very low value to observe the effect of throughput.
      // Throughput is the bottleneck.
      {1, 5, EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {1, 10, EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {1, 50, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {1, 100, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {1, 150, EFFECTIVE_CONNECTION_TYPE_2G},
      {1, 300, EFFECTIVE_CONNECTION_TYPE_2G},
      {1, 400, EFFECTIVE_CONNECTION_TYPE_3G},
      {1, 500, EFFECTIVE_CONNECTION_TYPE_3G},
      {1, 700, EFFECTIVE_CONNECTION_TYPE_4G},
      {1, 1000, EFFECTIVE_CONNECTION_TYPE_4G},
      {1, 1500, EFFECTIVE_CONNECTION_TYPE_4G},
      {1, 2500, EFFECTIVE_CONNECTION_TYPE_4G},
      // Set both RTT and throughput. RTT is the bottleneck.
      {3000, 25000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {700, 25000, EFFECTIVE_CONNECTION_TYPE_3G},
  };

  for (const auto& test : tests) {
    estimator.set_transport_rtt(
        base::TimeDelta::FromMilliseconds(test.transport_rtt_msec));
    estimator.set_recent_transport_rtt(
        base::TimeDelta::FromMilliseconds(test.transport_rtt_msec));
    estimator.set_downlink_throughput_kbps(test.downlink_throughput_kbps);
    estimator.set_recent_downlink_throughput_kbps(
        test.downlink_throughput_kbps);
    // Run one main frame request to force recomputation of effective connection
    // type.
    estimator.RunOneRequest();
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

TEST(NetworkQualityEstimatorTest, TestGetMetricsSince) {
  std::map<std::string, std::string> variation_params;

  const base::TimeDelta rtt_threshold_3g =
      base::TimeDelta::FromMilliseconds(30);
  const base::TimeDelta rtt_threshold_4g = base::TimeDelta::FromMilliseconds(1);

  variation_params["3G.ThresholdMedianHttpRTTMsec"] =
      base::IntToString(rtt_threshold_3g.InMilliseconds());
  variation_params["4G.ThresholdMedianHttpRTTMsec"] =
      base::IntToString(rtt_threshold_4g.InMilliseconds());
  variation_params["HalfLifeSeconds"] = "300000";

  TestNetworkQualityEstimator estimator(variation_params);
  base::TimeTicks now = base::TimeTicks::Now();
  base::TimeTicks old = now - base::TimeDelta::FromMilliseconds(1);
  ASSERT_NE(old, now);

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test");

  const int32_t old_downlink_kbps = 1;
  const base::TimeDelta old_url_rtt = base::TimeDelta::FromMilliseconds(1);
  const base::TimeDelta old_tcp_rtt = base::TimeDelta::FromMilliseconds(10);

  DCHECK_LT(old_url_rtt, rtt_threshold_3g);
  DCHECK_LT(old_tcp_rtt, rtt_threshold_3g);

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
  DCHECK_GT(new_url_rtt, rtt_threshold_3g);
  DCHECK_GT(new_tcp_rtt, rtt_threshold_3g);
  DCHECK_GT(new_url_rtt, rtt_threshold_4g);
  DCHECK_GT(new_tcp_rtt, rtt_threshold_4g);

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
    EffectiveConnectionType expected_effective_connection_type;
  } tests[] = {
      {now + base::TimeDelta::FromSeconds(10), false,
       base::TimeDelta::FromMilliseconds(0),
       base::TimeDelta::FromMilliseconds(0), 0, EFFECTIVE_CONNECTION_TYPE_4G},
      {now, true, new_url_rtt, new_tcp_rtt, new_downlink_kbps,
       EFFECTIVE_CONNECTION_TYPE_3G},
      {old - base::TimeDelta::FromMicroseconds(500), true, old_url_rtt,
       old_tcp_rtt, old_downlink_kbps, EFFECTIVE_CONNECTION_TYPE_4G},

  };
  for (const auto& test : tests) {
    base::TimeDelta http_rtt;
    base::TimeDelta transport_rtt;
    int32_t downstream_throughput_kbps;
    EXPECT_EQ(test.expect_network_quality_available,
              estimator.GetRecentHttpRTT(test.start_timestamp, &http_rtt));
    EXPECT_EQ(
        test.expect_network_quality_available,
        estimator.GetRecentTransportRTT(test.start_timestamp, &transport_rtt));
    EXPECT_EQ(test.expect_network_quality_available,
              estimator.GetRecentDownlinkThroughputKbps(
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
  estimator.SimulateNetworkChange(net::NetworkChangeNotifier::CONNECTION_WIFI,
                                  "test");

  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_EQ(1U, invalid_external_estimate_provider->update_count());
  EXPECT_FALSE(estimator.GetHttpRTT(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbps(&kbps));
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
  estimator.SimulateNetworkChange(net::NetworkChangeNotifier::CONNECTION_WIFI,
                                  "test");
  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_TRUE(estimator.GetHttpRTT(&rtt));
  EXPECT_FALSE(estimator.GetTransportRTT(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbps(&kbps));

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
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-1");
  EXPECT_TRUE(estimator.GetHttpRTT(&rtt));
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbps(&kbps));
  EXPECT_EQ(2U, test_external_estimate_provider->update_count());

  test_external_estimate_provider->set_should_notify_delegate(false);
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test-2");
  EXPECT_EQ(3U, test_external_estimate_provider->update_count());
  // Estimates are unavailable because external estimate provider never
  // notifies network quality estimator of the updated estimates.
  EXPECT_FALSE(estimator.GetHttpRTT(&rtt));
  EXPECT_FALSE(estimator.GetDownlinkThroughputKbps(&kbps));
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
  estimator.SimulateNetworkChange(net::NetworkChangeNotifier::CONNECTION_WIFI,
                                  "test");

  base::TimeDelta rtt;
  // Estimate provided by network quality estimator should match the estimate
  // provided by external estimate provider.
  EXPECT_TRUE(estimator.GetHttpRTT(&rtt));
  EXPECT_EQ(external_estimate_provider_rtt, rtt);

  int32_t kbps;
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbps(&kbps));
  EXPECT_EQ(external_estimate_provider_downstream_throughput, kbps);

  TestDelegate test_delegate;
  TestURLRequestContext context(true);
  context.set_network_quality_estimator(&estimator);
  context.Init();

  std::unique_ptr<URLRequest> request(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request->Start();
  base::RunLoop().Run();

  EXPECT_TRUE(estimator.GetHttpRTT(&rtt));
  EXPECT_NE(external_estimate_provider_rtt, rtt);

  EXPECT_TRUE(estimator.GetDownlinkThroughputKbps(&kbps));
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
    EXPECT_FALSE(estimator.GetHttpRTT(&rtt));
    int32_t kbps;
    EXPECT_FALSE(estimator.GetDownlinkThroughputKbps(&kbps));

    TestDelegate test_delegate;
    TestURLRequestContext context(true);
    context.set_network_quality_estimator(&estimator);
    context.Init();

    std::unique_ptr<URLRequest> request(context.CreateRequest(
        estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
    request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
    request->Start();
    base::RunLoop().Run();

    EXPECT_EQ(test.allow_small_localhost_requests, estimator.GetHttpRTT(&rtt));
    EXPECT_EQ(test.allow_small_localhost_requests,
              estimator.GetDownlinkThroughputKbps(&kbps));
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

  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_2G);
  tick_clock_ptr->Advance(base::TimeDelta::FromMinutes(60));

  std::unique_ptr<URLRequest> request(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request->Start();
  base::RunLoop().Run();
  EXPECT_EQ(1U, observer.effective_connection_types().size());
  histogram_tester.ExpectUniqueSample("NQE.MainFrame.EffectiveConnectionType",
                                      EFFECTIVE_CONNECTION_TYPE_2G, 1);
  histogram_tester.ExpectUniqueSample(
      "NQE.MainFrame.EffectiveConnectionType.Unknown",
      EFFECTIVE_CONNECTION_TYPE_2G, 1);

  // Next request should not trigger recomputation of effective connection type
  // since there has been no change in the clock.
  std::unique_ptr<URLRequest> request2(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request2->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request2->Start();
  base::RunLoop().Run();
  EXPECT_EQ(1U, observer.effective_connection_types().size());

  // Change in connection type should send out notification to the observers.
  estimator.set_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_3G);
  estimator.SimulateNetworkChange(NetworkChangeNotifier::CONNECTION_WIFI,
                                  "test");
  EXPECT_EQ(2U, observer.effective_connection_types().size());

  // A change in effective connection type does not trigger notification to the
  // observers, since it is not accompanied by any new observation or a network
  // change event.
  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_3G);
  EXPECT_EQ(2U, observer.effective_connection_types().size());
}

// Tests that the network quality is computed at the specified interval, and
// that the network quality observers are notified of any change.
TEST(NetworkQualityEstimatorTest, TestRTTAndThroughputEstimatesObserver) {
  base::HistogramTester histogram_tester;
  std::unique_ptr<base::SimpleTestTickClock> tick_clock(
      new base::SimpleTestTickClock());
  base::SimpleTestTickClock* tick_clock_ptr = tick_clock.get();

  TestRTTAndThroughputEstimatesObserver observer;
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.AddRTTAndThroughputEstimatesObserver(&observer);
  estimator.SetTickClockForTesting(std::move(tick_clock));

  TestDelegate test_delegate;
  TestURLRequestContext context(true);
  context.set_network_quality_estimator(&estimator);
  context.Init();

  EXPECT_EQ(nqe::internal::InvalidRTT(), observer.http_rtt());
  EXPECT_EQ(nqe::internal::InvalidRTT(), observer.transport_rtt());
  EXPECT_EQ(nqe::internal::kInvalidThroughput,
            observer.downstream_throughput_kbps());
  int notifications_received = observer.notifications_received();
  EXPECT_EQ(0, notifications_received);

  base::TimeDelta http_rtt(base::TimeDelta::FromMilliseconds(100));
  base::TimeDelta transport_rtt(base::TimeDelta::FromMilliseconds(200));
  int32_t downstream_throughput_kbps(300);
  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_2G);
  estimator.set_recent_http_rtt(http_rtt);
  estimator.set_recent_transport_rtt(transport_rtt);
  estimator.set_recent_downlink_throughput_kbps(downstream_throughput_kbps);
  tick_clock_ptr->Advance(base::TimeDelta::FromMinutes(60));

  std::unique_ptr<URLRequest> request(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request->Start();
  base::RunLoop().Run();
  EXPECT_EQ(http_rtt, observer.http_rtt());
  EXPECT_EQ(transport_rtt, observer.transport_rtt());
  EXPECT_EQ(downstream_throughput_kbps, observer.downstream_throughput_kbps());
  EXPECT_LE(1, observer.notifications_received() - notifications_received);
  notifications_received = observer.notifications_received();

  // The next request should not trigger recomputation of RTT or throughput
  // since there has been no change in the clock.
  std::unique_ptr<URLRequest> request2(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request2->Start();
  base::RunLoop().Run();
  EXPECT_LE(1, observer.notifications_received() - notifications_received);
  notifications_received = observer.notifications_received();

  // A change in the connection type should send out notification to the
  // observers.
  estimator.set_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_3G);
  estimator.SimulateNetworkChange(NetworkChangeNotifier::CONNECTION_WIFI,
                                  "test");
  EXPECT_LE(1, observer.notifications_received() - notifications_received);
  notifications_received = observer.notifications_received();

  // A change in effective connection type does not trigger notification to the
  // observers, since it is not accompanied by any new observation or a network
  // change event.
  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_3G);
  EXPECT_EQ(0, observer.notifications_received() - notifications_received);
}

// Tests that the effective connection type is computed on every RTT
// observation if the last computed effective connection type was unknown.
TEST(NetworkQualityEstimatorTest, UnknownEffectiveConnectionType) {
  std::unique_ptr<base::SimpleTestTickClock> tick_clock(
      new base::SimpleTestTickClock());
  base::SimpleTestTickClock* tick_clock_ptr = tick_clock.get();

  TestEffectiveConnectionTypeObserver observer;
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.SetTickClockForTesting(std::move(tick_clock));
  estimator.AddEffectiveConnectionTypeObserver(&observer);
  tick_clock_ptr->Advance(base::TimeDelta::FromMinutes(60));

  size_t expected_effective_connection_type_notifications = 0;
  estimator.set_recent_effective_connection_type(
      EFFECTIVE_CONNECTION_TYPE_UNKNOWN);
  // Run one main frame request to force recomputation of effective connection
  // type.
  estimator.RunOneRequest();
  estimator.SimulateNetworkChange(NetworkChangeNotifier::CONNECTION_WIFI,
                                  "test");

  NetworkQualityEstimator::RttObservation rtt_observation(
      base::TimeDelta::FromSeconds(5), tick_clock_ptr->NowTicks(),
      NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST);

  for (size_t i = 0; i < 10; ++i) {
    estimator.NotifyObserversOfRTT(rtt_observation);
    EXPECT_EQ(expected_effective_connection_type_notifications,
              observer.effective_connection_types().size());
  }
  estimator.set_recent_effective_connection_type(
      EFFECTIVE_CONNECTION_TYPE_SLOW_2G);
  // Even though there are 10 RTT samples already available, the addition of one
  // more RTT sample should trigger recomputation of the effective connection
  // type since the last computed effective connection type was unknown.
  estimator.NotifyObserversOfRTT(NetworkQualityEstimator::RttObservation(
      base::TimeDelta::FromSeconds(5), tick_clock_ptr->NowTicks(),
      NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
  ++expected_effective_connection_type_notifications;
  EXPECT_EQ(expected_effective_connection_type_notifications,
            observer.effective_connection_types().size());
}

// Tests that the effective connection type is computed regularly depending
// on the number of RTT and bandwidth samples.
TEST(NetworkQualityEstimatorTest,
     AdaptiveRecomputationEffectiveConnectionType) {
  base::HistogramTester histogram_tester;
  std::unique_ptr<base::SimpleTestTickClock> tick_clock(
      new base::SimpleTestTickClock());
  base::SimpleTestTickClock* tick_clock_ptr = tick_clock.get();

  TestEffectiveConnectionTypeObserver observer;
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.SetTickClockForTesting(std::move(tick_clock));
  estimator.SimulateNetworkChange(NetworkChangeNotifier::CONNECTION_WIFI,
                                  "test");
  estimator.AddEffectiveConnectionTypeObserver(&observer);

  TestDelegate test_delegate;
  TestURLRequestContext context(true);
  context.set_network_quality_estimator(&estimator);
  context.Init();

  EXPECT_EQ(0U, observer.effective_connection_types().size());

  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_2G);
  tick_clock_ptr->Advance(base::TimeDelta::FromMinutes(60));

  std::unique_ptr<URLRequest> request(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request->Start();
  base::RunLoop().Run();
  EXPECT_EQ(1U, observer.effective_connection_types().size());
  histogram_tester.ExpectUniqueSample("NQE.MainFrame.EffectiveConnectionType",
                                      EFFECTIVE_CONNECTION_TYPE_2G, 1);
  histogram_tester.ExpectUniqueSample(
      "NQE.MainFrame.EffectiveConnectionType.WiFi",
      EFFECTIVE_CONNECTION_TYPE_2G, 1);

  size_t expected_effective_connection_type_notifications = 1;
  EXPECT_EQ(expected_effective_connection_type_notifications,
            observer.effective_connection_types().size());

  EXPECT_EQ(expected_effective_connection_type_notifications,
            estimator.rtt_observations_.Size());

  // Increase the number of RTT observations. Every time the number of RTT
  // observations is more than doubled, effective connection type must be
  // recomputed and notified to observers.
  for (size_t repetition = 0; repetition < 2; ++repetition) {
    // Change the effective connection type so that the observers are
    // notified when the effective connection type is recomputed.
    if (repetition % 2 == 0) {
      estimator.set_recent_effective_connection_type(
          EFFECTIVE_CONNECTION_TYPE_SLOW_2G);
    } else {
      estimator.set_recent_effective_connection_type(
          EFFECTIVE_CONNECTION_TYPE_3G);
    }
    size_t rtt_observations_count = estimator.rtt_observations_.Size() * 0.5;
    // Increase the number of RTT observations to more than twice the number
    // of current observations. This should trigger recomputation of
    // effective connection type.
    for (size_t i = 0; i < rtt_observations_count + 1; ++i) {
      estimator.rtt_observations_.AddObservation(
          NetworkQualityEstimator::RttObservation(
              base::TimeDelta::FromSeconds(5), tick_clock_ptr->NowTicks(),
              NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));

      estimator.NotifyObserversOfRTT(NetworkQualityEstimator::RttObservation(
          base::TimeDelta::FromSeconds(5), tick_clock_ptr->NowTicks(),
          NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));

      if (i == rtt_observations_count) {
        // Effective connection type must be recomputed since the number of RTT
        // samples are now more than twice the number of RTT samples that were
        // available when effective connection type was last computed.
        ++expected_effective_connection_type_notifications;
      }
      EXPECT_EQ(expected_effective_connection_type_notifications,
                observer.effective_connection_types().size());
    }
  }
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
  request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request->Start();
  base::RunLoop().Run();

  std::unique_ptr<URLRequest> request2(context.CreateRequest(
      estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
  request2->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request2->Start();
  base::RunLoop().Run();

  // Both RTT and downstream throughput should be updated.
  base::TimeDelta rtt;
  EXPECT_TRUE(estimator.GetHttpRTT(&rtt));

  int32_t throughput;
  EXPECT_TRUE(estimator.GetDownlinkThroughputKbps(&throughput));

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

  EXPECT_FALSE(estimator.GetTransportRTT(&rtt));

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

  EXPECT_TRUE(estimator.GetTransportRTT(&rtt));
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
  EXPECT_FALSE(estimator.GetHttpRTT(&rtt));
  EXPECT_FALSE(estimator.GetTransportRTT(&rtt));

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
    request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
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
  EXPECT_TRUE(estimator.GetHttpRTT(&rtt));
  EXPECT_TRUE(estimator.GetTransportRTT(&rtt));

  estimator.SimulateNetworkChange(
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
  histogram_tester.ExpectTotalCount("NQE.MainFrame.TransportRTT.Percentile50",
                                    num_requests);
  histogram_tester.ExpectTotalCount(
      "NQE.MainFrame.TransportRTT.Percentile50.Unknown", num_requests);
  histogram_tester.ExpectTotalCount("NQE.MainFrame.EffectiveConnectionType",
                                    num_requests);
  histogram_tester.ExpectTotalCount(
      "NQE.MainFrame.EffectiveConnectionType.Unknown", num_requests);
  histogram_tester.ExpectBucketCount(
      "NQE.MainFrame.EffectiveConnectionType.Unknown",
      EFFECTIVE_CONNECTION_TYPE_UNKNOWN, 1);
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
    EffectiveConnectionType effective_connection_type;
    EffectiveConnectionType recent_effective_connection_type;
  } tests[] = {
      {base::TimeDelta::FromMilliseconds(expected_rtt_msec),
       base::TimeDelta::FromMilliseconds(expected_rtt_msec),
       expected_downstream_throughput_kbps, expected_downstream_throughput_kbps,
       EFFECTIVE_CONNECTION_TYPE_2G, EFFECTIVE_CONNECTION_TYPE_2G},

      {
          base::TimeDelta::FromMilliseconds(expected_rtt_msec + 1),
          base::TimeDelta::FromMilliseconds(expected_rtt_msec),
          expected_downstream_throughput_kbps + 1,
          expected_downstream_throughput_kbps, EFFECTIVE_CONNECTION_TYPE_3G,
          EFFECTIVE_CONNECTION_TYPE_2G,
      },
      {
          base::TimeDelta::FromMilliseconds(expected_rtt_msec - 1),
          base::TimeDelta::FromMilliseconds(expected_rtt_msec),
          expected_downstream_throughput_kbps - 1,
          expected_downstream_throughput_kbps,
          EFFECTIVE_CONNECTION_TYPE_SLOW_2G, EFFECTIVE_CONNECTION_TYPE_2G,
      },
  };

  for (const auto& accuracy_recording_delay : accuracy_recording_delays) {
    for (const auto& test : tests) {
      std::unique_ptr<base::SimpleTestTickClock> tick_clock(
          new base::SimpleTestTickClock());
      base::SimpleTestTickClock* tick_clock_ptr = tick_clock.get();
      tick_clock_ptr->Advance(base::TimeDelta::FromSeconds(1));

      std::unique_ptr<ExternalEstimateProvider> external_estimate_provider(
          new TestExternalEstimateProvider(test.rtt, 0));

      std::map<std::string, std::string> variation_params;
      TestNetworkQualityEstimator estimator(
          variation_params, std::move(external_estimate_provider));

      estimator.SetTickClockForTesting(std::move(tick_clock));
      estimator.SimulateNetworkChange(
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
      request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
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

      histogram_tester.ExpectUniqueSample(
          "NQE.ExternalEstimateProvider.RTT.Accuracy.EstimatedObservedDiff." +
              sign_suffix_with_one_sample + "." + interval_value + ".60_140",
          diff, 1);
      histogram_tester.ExpectTotalCount(
          "NQE.ExternalEstimateProvider.RTT.Accuracy.EstimatedObservedDiff." +
              sign_suffix_with_zero_samples + "." + interval_value + ".60_140",
          0);
    }
  }
}

TEST(NetworkQualityEstimatorTest, TestRecordNetworkIDAvailability) {
  base::HistogramTester histogram_tester;
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);

  // The NetworkID is recorded as available on Wi-Fi connection.
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-1");
  histogram_tester.ExpectUniqueSample("NQE.NetworkIdAvailable", 1, 1);

  // The histogram is not recorded on an unknown connection.
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN, "");
  histogram_tester.ExpectTotalCount("NQE.NetworkIdAvailable", 1);

  // The NetworkID is recorded as not being available on a Wi-Fi connection
  // with an empty SSID.
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "");
  histogram_tester.ExpectBucketCount("NQE.NetworkIdAvailable", 0, 1);
  histogram_tester.ExpectTotalCount("NQE.NetworkIdAvailable", 2);

  // The NetworkID is recorded as being available on a Wi-Fi connection.
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-1");
  histogram_tester.ExpectBucketCount("NQE.NetworkIdAvailable", 1, 2);
  histogram_tester.ExpectTotalCount("NQE.NetworkIdAvailable", 3);

  // The NetworkID is recorded as being available on a cellular connection.
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test-1");
  histogram_tester.ExpectBucketCount("NQE.NetworkIdAvailable", 1, 3);
  histogram_tester.ExpectTotalCount("NQE.NetworkIdAvailable", 4);
}

// Tests that the correlation histogram is recorded correctly based on
// correlation logging probability set in the variation params.
TEST(NetworkQualityEstimatorTest, CorrelationHistogram) {
  // Match the values set in network_quality_estimator.cc.
  static const int32_t kTrimBits = 5;
  static const int32_t kBitsPerMetric = 7;

  const struct {
    bool use_transport_rtt;
    double rand_double;
    double correlation_logging_probability;
    base::TimeDelta transport_rtt;
    int32_t expected_transport_rtt_milliseconds;
    base::TimeDelta http_rtt;
    int32_t expected_http_rtt_milliseconds;
    int32_t downstream_throughput_kbps;
    int32_t expected_downstream_throughput_kbps;

  } tests[] = {
      {
          // Verify that the metric is not recorded if the logging probability
          // is set to 0.0.
          false, 0.5, 0.0, base::TimeDelta::FromSeconds(1), 1000 >> kTrimBits,
          base::TimeDelta::FromSeconds(2), 2000 >> kTrimBits, 3000,
          3000 >> kTrimBits,
      },
      {
          // Verify that the metric is not recorded if the logging probability
          // is lower than the value returned by the random number generator.
          false, 0.3, 0.1, base::TimeDelta::FromSeconds(1), 1000 >> kTrimBits,
          base::TimeDelta::FromSeconds(2), 2000 >> kTrimBits, 3000,
          3000 >> kTrimBits,
      },
      {
          // Verify that the metric is recorded if the logging probability is
          // higher than the value returned by the random number generator.
          false, 0.3, 0.4, base::TimeDelta::FromSeconds(1), 1000 >> kTrimBits,
          base::TimeDelta::FromSeconds(2), 2000 >> kTrimBits, 3000,
          3000 >> kTrimBits,
      },
      {
          // Verify that the metric is recorded if the logging probability is
          // set to 1.0.
          false, 0.5, 1.0, base::TimeDelta::FromSeconds(1), 1000 >> kTrimBits,
          base::TimeDelta::FromSeconds(2), 2000 >> kTrimBits, 3000,
          3000 >> kTrimBits,
      },
      {
          // Verify that the metric is recorded if the logging probability is
          // set to 1.0.
          true, 0.5, 1.0, base::TimeDelta::FromSeconds(1), 1000 >> kTrimBits,
          base::TimeDelta::FromSeconds(2), 2000 >> kTrimBits, 3000,
          3000 >> kTrimBits,
      },
      {
          // Verify that if the metric is larger than
          // 2^(kBitsPerMetric + kTrimBits), it is rounded down to
          // (2^(kBitsPerMetric + kTrimBits) - 1) >> kTrimBits.
          false, 0.5, 1.0, base::TimeDelta::FromSeconds(10), 4095 >> kTrimBits,
          base::TimeDelta::FromSeconds(20), 4095 >> kTrimBits, 30000,
          4095 >> kTrimBits,
      },
  };

  for (const auto& test : tests) {
    base::HistogramTester histogram_tester;

    std::map<std::string, std::string> variation_params;
    variation_params["correlation_logging_probability"] =
        base::DoubleToString(test.correlation_logging_probability);
    if (test.use_transport_rtt) {
      variation_params["effective_connection_type_algorithm"] =
          "TransportRTTOrDownstreamThroughput";
    }
    TestNetworkQualityEstimator estimator(variation_params);

    estimator.set_transport_rtt(test.transport_rtt);
    estimator.set_recent_transport_rtt(test.transport_rtt);
    estimator.set_http_rtt(test.http_rtt);
    estimator.set_recent_http_rtt(test.http_rtt);
    estimator.set_downlink_throughput_kbps(test.downstream_throughput_kbps);
    estimator.set_rand_double(test.rand_double);

    TestDelegate test_delegate;
    TestURLRequestContext context(true);
    context.set_network_quality_estimator(&estimator);
    context.Init();

    // Start a main-frame request that should cause network quality estimator to
    // record the network quality at the last main frame request.
    std::unique_ptr<URLRequest> request_1(context.CreateRequest(
        estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
    request_1->SetLoadFlags(request_1->load_flags() |
                            LOAD_MAIN_FRAME_DEPRECATED);
    request_1->Start();
    base::RunLoop().Run();
    histogram_tester.ExpectTotalCount(
        "NQE.Correlation.ResourceLoadTime.0Kb_128Kb", 0);

    // Start another main-frame request which should cause network quality
    // estimator to record the correlation UMA.
    std::unique_ptr<URLRequest> request_2(context.CreateRequest(
        estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
    request_2->Start();
    base::RunLoop().Run();

    if (test.rand_double >= test.correlation_logging_probability) {
      histogram_tester.ExpectTotalCount(
          "NQE.Correlation.ResourceLoadTime.0Kb_128Kb", 0);
      continue;
    }
    histogram_tester.ExpectTotalCount(
        "NQE.Correlation.ResourceLoadTime.0Kb_128Kb", 1);
    std::vector<base::Bucket> buckets = histogram_tester.GetAllSamples(
        "NQE.Correlation.ResourceLoadTime.0Kb_128Kb");
    // Get the bits at index 0-10 which contain the RTT.
    // 128 is 2^kBitsPerMetric.
    if (test.use_transport_rtt) {
      EXPECT_EQ(test.expected_transport_rtt_milliseconds,
                buckets.at(0).min >> kBitsPerMetric >> kBitsPerMetric >>
                    kBitsPerMetric);
    } else {
      EXPECT_EQ(test.expected_http_rtt_milliseconds,
                buckets.at(0).min >> kBitsPerMetric >> kBitsPerMetric >>
                    kBitsPerMetric);
    }

    // Get the bits at index 11-17 which contain the downstream throughput.
    EXPECT_EQ(test.expected_downstream_throughput_kbps,
              (buckets.at(0).min >> kBitsPerMetric >> kBitsPerMetric) % 128);

    // Get the bits at index 18-24 which contain the resource fetch time.
    EXPECT_LE(0, (buckets.at(0).min >> kBitsPerMetric) % 128);

    // Get the bits at index 25-31 which contain the resource load size.
    EXPECT_LE(0, (buckets.at(0).min) % 128);
  }
}

class TestNetworkQualitiesCacheObserver
    : public nqe::internal::NetworkQualityStore::NetworkQualitiesCacheObserver {
 public:
  TestNetworkQualitiesCacheObserver()
      : network_id_(net::NetworkChangeNotifier::CONNECTION_UNKNOWN,
                    std::string()),
        notification_received_(0) {}
  ~TestNetworkQualitiesCacheObserver() override {}

  void OnChangeInCachedNetworkQuality(
      const nqe::internal::NetworkID& network_id,
      const nqe::internal::CachedNetworkQuality& cached_network_quality)
      override {
    network_id_ = network_id;
    notification_received_++;
  }

  size_t get_notification_received_and_reset() {
    size_t notification_received = notification_received_;
    notification_received_ = 0;
    return notification_received;
  }

  nqe::internal::NetworkID network_id() const { return network_id_; }

 private:
  nqe::internal::NetworkID network_id_;
  size_t notification_received_;
  DISALLOW_COPY_AND_ASSIGN(TestNetworkQualitiesCacheObserver);
};

TEST(NetworkQualityEstimatorTest, CacheObserver) {
  TestNetworkQualitiesCacheObserver observer;
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params);

  // Add |observer| as a persistent caching observer.
  estimator.AddNetworkQualitiesCacheObserver(&observer);

  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_3G);
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN, "test3g");
  estimator.RunOneRequest();
  EXPECT_EQ(1u, observer.get_notification_received_and_reset());
  EXPECT_EQ("test3g", observer.network_id().id);

  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_2G);
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test2g");
  // One notification should be received for the previous network
  // ("test3g") right before the connection change event. The second
  // notification should be received for the second network ("test2g").
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2u, observer.get_notification_received_and_reset());
  estimator.RunOneRequest();
  EXPECT_EQ("test2g", observer.network_id().id);

  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_4G);
  // Start multiple requests, but there should be only one notification
  // received, since the effective connection type does not change.
  estimator.RunOneRequest();
  estimator.RunOneRequest();
  estimator.RunOneRequest();
  EXPECT_EQ(1u, observer.get_notification_received_and_reset());

  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_2G);
  estimator.RunOneRequest();
  EXPECT_EQ(1u, observer.get_notification_received_and_reset());

  // Remove |observer|, and it should not receive any notifications.
  estimator.RemoveNetworkQualitiesCacheObserver(&observer);
  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_3G);
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test2g");
  EXPECT_EQ(0u, observer.get_notification_received_and_reset());
  estimator.RunOneRequest();
  EXPECT_EQ(0u, observer.get_notification_received_and_reset());
}

// Tests that the value of the effective connection type can be forced through
// field trial parameters.
TEST(NetworkQualityEstimatorTest,
     ForceEffectiveConnectionTypeThroughFieldTrial) {
  for (int i = 0; i < EFFECTIVE_CONNECTION_TYPE_LAST; ++i) {
    std::map<std::string, std::string> variation_params;
    variation_params["force_effective_connection_type"] =
        GetNameForEffectiveConnectionType(
            static_cast<EffectiveConnectionType>(i));
    TestNetworkQualityEstimator estimator(variation_params);

    TestEffectiveConnectionTypeObserver observer;
    estimator.AddEffectiveConnectionTypeObserver(&observer);

    TestDelegate test_delegate;
    TestURLRequestContext context(true);
    context.set_network_quality_estimator(&estimator);
    context.Init();

    EXPECT_EQ(0U, observer.effective_connection_types().size());

    std::unique_ptr<URLRequest> request(context.CreateRequest(
        estimator.GetEchoURL(), DEFAULT_PRIORITY, &test_delegate));
    request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
    request->Start();
    base::RunLoop().Run();

    EXPECT_EQ(i, estimator.GetEffectiveConnectionType());

    size_t expected_count = static_cast<EffectiveConnectionType>(i) ==
                                    EFFECTIVE_CONNECTION_TYPE_UNKNOWN
                                ? 0
                                : 1;
    ASSERT_EQ(expected_count, observer.effective_connection_types().size());
    if (expected_count == 1) {
      EffectiveConnectionType last_notified_type =
          observer.effective_connection_types().at(
              observer.effective_connection_types().size() - 1);
      EXPECT_EQ(i, last_notified_type);
    }
  }
}

}  // namespace net

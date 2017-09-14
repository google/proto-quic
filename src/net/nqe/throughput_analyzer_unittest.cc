// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/throughput_analyzer.h"

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/containers/circular_deque.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/dns/mock_host_resolver.h"
#include "net/log/test_net_log.h"
#include "net/nqe/network_quality_estimator_params.h"
#include "net/nqe/network_quality_estimator_util.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace nqe {

namespace {

class TestThroughputAnalyzer : public internal::ThroughputAnalyzer {
 public:
  explicit TestThroughputAnalyzer(NetworkQualityEstimatorParams* params)
      : internal::ThroughputAnalyzer(
            params,
            base::ThreadTaskRunnerHandle::Get(),
            base::Bind(
                &TestThroughputAnalyzer::OnNewThroughputObservationAvailable,
                base::Unretained(this)),
            std::make_unique<BoundTestNetLog>()->bound()),
        throughput_observations_received_(0),
        bits_received_(0) {}

  ~TestThroughputAnalyzer() override {}

  int32_t throughput_observations_received() const {
    return throughput_observations_received_;
  }

  void OnNewThroughputObservationAvailable(int32_t downstream_kbps) {
    throughput_observations_received_++;
  }

  int64_t GetBitsReceived() const override { return bits_received_; }

  void IncrementBitsReceived(int64_t additional_bits_received) {
    bits_received_ += additional_bits_received;
  }

  // Uses a mock resolver to force example.com to resolve to a public IP
  // address.
  void AddIPAddressResolution(TestURLRequestContext* context) {
    scoped_refptr<net::RuleBasedHostResolverProc> rules(
        new net::RuleBasedHostResolverProc(nullptr));
    // example1.com resolves to a public IP address.
    rules->AddRule("example.com", "27.0.0.3");
    mock_host_resolver_.set_rules(rules.get());
    context->set_host_resolver(&mock_host_resolver_);
  }

  using internal::ThroughputAnalyzer::disable_throughput_measurements;

 private:
  int throughput_observations_received_;

  int64_t bits_received_;

  MockCachingHostResolver mock_host_resolver_;

  DISALLOW_COPY_AND_ASSIGN(TestThroughputAnalyzer);
};

TEST(ThroughputAnalyzerTest, MaximumRequests) {
  const struct {
    bool use_local_requests;
  } tests[] = {{
                   false,
               },
               {
                   true,
               }};

  for (const auto& test : tests) {
    std::map<std::string, std::string> variation_params;
    NetworkQualityEstimatorParams params(variation_params);
    TestThroughputAnalyzer throughput_analyzer(&params);

    TestDelegate test_delegate;
    TestURLRequestContext context;
    throughput_analyzer.AddIPAddressResolution(&context);

    ASSERT_FALSE(throughput_analyzer.disable_throughput_measurements());
    base::circular_deque<std::unique_ptr<URLRequest>> requests;

    // Start more requests than the maximum number of requests that can be held
    // in the memory.
    const std::string url = test.use_local_requests
                                ? "http://127.0.0.1/test.html"
                                : "http://example.com/test.html";

    EXPECT_EQ(
        test.use_local_requests,
        nqe::internal::IsPrivateHost(
            context.host_resolver(),
            HostPortPair(GURL(url).host(), GURL(url).EffectiveIntPort())));
    for (size_t i = 0; i < 1000; ++i) {
      std::unique_ptr<URLRequest> request(
          context.CreateRequest(GURL(url), DEFAULT_PRIORITY, &test_delegate,
                                TRAFFIC_ANNOTATION_FOR_TESTS));
      throughput_analyzer.NotifyStartTransaction(*(request.get()));
      requests.push_back(std::move(request));
    }
    // Too many local requests should cause the |throughput_analyzer| to disable
    // throughput measurements.
    EXPECT_NE(test.use_local_requests,
              throughput_analyzer.IsCurrentlyTrackingThroughput());
  }
}

// Tests that the throughput observation is taken only if there are sufficient
// number of requests in-flight.
TEST(ThroughputAnalyzerTest, TestMinRequestsForThroughputSample) {
  std::map<std::string, std::string> variation_params;
  NetworkQualityEstimatorParams params(variation_params);

  for (size_t num_requests = 1;
       num_requests <= params.throughput_min_requests_in_flight() + 1;
       ++num_requests) {
    TestThroughputAnalyzer throughput_analyzer(&params);
    TestDelegate test_delegate;
    TestURLRequestContext context;
    throughput_analyzer.AddIPAddressResolution(&context);
    std::vector<std::unique_ptr<URLRequest>> requests_not_local;

    for (size_t i = 0; i < num_requests; ++i) {
      std::unique_ptr<URLRequest> request_not_local(context.CreateRequest(
          GURL("http://example.com/echo.html"), DEFAULT_PRIORITY,
          &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
      request_not_local->Start();
      requests_not_local.push_back(std::move(request_not_local));
    }

    base::RunLoop().Run();

    EXPECT_EQ(0, throughput_analyzer.throughput_observations_received());

    for (size_t i = 0; i < requests_not_local.size(); ++i) {
      throughput_analyzer.NotifyStartTransaction(*requests_not_local.at(i));
    }

    // Increment the bytes received count to emulate the bytes received for
    // |request_local| and |requests_not_local|.
    throughput_analyzer.IncrementBitsReceived(100 * 1000 * 8);

    for (size_t i = 0; i < requests_not_local.size(); ++i) {
      throughput_analyzer.NotifyRequestCompleted(*requests_not_local.at(i));
    }
    base::RunLoop().RunUntilIdle();

    int expected_throughput_observations =
        num_requests >= params.throughput_min_requests_in_flight() ? 1 : 0;
    EXPECT_EQ(expected_throughput_observations,
              throughput_analyzer.throughput_observations_received());
  }
}

// Tests if the throughput observation is taken correctly when local and network
// requests overlap.
TEST(ThroughputAnalyzerTest, TestThroughputWithMultipleRequestsOverlap) {
  static const struct {
    bool start_local_request;
    bool local_request_completes_first;
    bool expect_throughput_observation;
  } tests[] = {
      {
          false, false, true,
      },
      {
          true, false, false,
      },
      {
          true, true, true,
      },
  };

  for (const auto& test : tests) {
    // Localhost requests are not allowed for estimation purposes.
    std::map<std::string, std::string> variation_params;
    NetworkQualityEstimatorParams params(variation_params);
    TestThroughputAnalyzer throughput_analyzer(&params);

    TestDelegate test_delegate;
    TestURLRequestContext context;
    throughput_analyzer.AddIPAddressResolution(&context);

    std::unique_ptr<URLRequest> request_local;

    std::vector<std::unique_ptr<URLRequest>> requests_not_local;

    for (size_t i = 0; i < params.throughput_min_requests_in_flight(); ++i) {
      std::unique_ptr<URLRequest> request_not_local(context.CreateRequest(
          GURL("http://example.com/echo.html"), DEFAULT_PRIORITY,
          &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
      request_not_local->Start();
      requests_not_local.push_back(std::move(request_not_local));
    }

    if (test.start_local_request) {
      request_local = context.CreateRequest(GURL("http://127.0.0.1/echo.html"),
                                            DEFAULT_PRIORITY, &test_delegate,
                                            TRAFFIC_ANNOTATION_FOR_TESTS);
      request_local->Start();
    }

    base::RunLoop().Run();

    EXPECT_EQ(0, throughput_analyzer.throughput_observations_received());

    // If |test.start_local_request| is true, then |request_local| starts
    // before |request_not_local|, and ends after |request_not_local|. Thus,
    // network quality estimator should not get a chance to record throughput
    // observation from |request_not_local| because of ongoing local request
    // at all times.
    if (test.start_local_request)
      throughput_analyzer.NotifyStartTransaction(*request_local);

    for (size_t i = 0; i < requests_not_local.size(); ++i) {
      throughput_analyzer.NotifyStartTransaction(*requests_not_local.at(i));
    }

    if (test.local_request_completes_first) {
      ASSERT_TRUE(test.start_local_request);
      throughput_analyzer.NotifyRequestCompleted(*request_local);
    }

    // Increment the bytes received count to emulate the bytes received for
    // |request_local| and |requests_not_local|.
    throughput_analyzer.IncrementBitsReceived(100 * 1000 * 8);

    for (size_t i = 0; i < requests_not_local.size(); ++i) {
      throughput_analyzer.NotifyRequestCompleted(*requests_not_local.at(i));
    }
    if (test.start_local_request && !test.local_request_completes_first)
      throughput_analyzer.NotifyRequestCompleted(*request_local);

    base::RunLoop().RunUntilIdle();

    int expected_throughput_observations =
        test.expect_throughput_observation ? 1 : 0;
    EXPECT_EQ(expected_throughput_observations,
              throughput_analyzer.throughput_observations_received());
  }
}

// Tests if the throughput observation is taken correctly when two network
// requests overlap.
TEST(ThroughputAnalyzerTest, TestThroughputWithNetworkRequestsOverlap) {
  static const struct {
    size_t throughput_min_requests_in_flight;
    size_t number_requests_in_flight;
    int64_t increment_bits;
    bool expect_throughput_observation;
  } tests[] = {
      {
          1, 2, 100 * 1000 * 8, true,
      },
      {
          3, 1, 100 * 1000 * 8, false,
      },
      {
          3, 2, 100 * 1000 * 8, false,
      },
      {
          3, 3, 100 * 1000 * 8, true,
      },
      {
          3, 4, 100 * 1000 * 8, true,
      },
      {
          1, 2, 1, false,
      },
  };

  for (const auto& test : tests) {
    // Localhost requests are not allowed for estimation purposes.
    std::map<std::string, std::string> variation_params;
    variation_params["throughput_min_requests_in_flight"] =
        base::IntToString(test.throughput_min_requests_in_flight);
    NetworkQualityEstimatorParams params(variation_params);
    TestThroughputAnalyzer throughput_analyzer(&params);
    TestDelegate test_delegate;
    TestURLRequestContext context;
    throughput_analyzer.AddIPAddressResolution(&context);

    EXPECT_EQ(0, throughput_analyzer.throughput_observations_received());

    std::vector<std::unique_ptr<URLRequest>> requests_in_flight;

    for (size_t i = 0; i < test.number_requests_in_flight; ++i) {
      std::unique_ptr<URLRequest> request_network_1 = context.CreateRequest(
          GURL("http://example.com/echo.html"), DEFAULT_PRIORITY,
          &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS);
      requests_in_flight.push_back(std::move(request_network_1));
      requests_in_flight.back()->Start();
    }

    base::RunLoop().Run();

    EXPECT_EQ(0, throughput_analyzer.throughput_observations_received());

    for (size_t i = 0; i < test.number_requests_in_flight; ++i) {
      URLRequest* request = requests_in_flight.at(i).get();
      throughput_analyzer.NotifyStartTransaction(*request);
    }

    // Increment the bytes received count to emulate the bytes received for
    // |request_network_1| and |request_network_2|.
    throughput_analyzer.IncrementBitsReceived(test.increment_bits);

    for (size_t i = 0; i < test.number_requests_in_flight; ++i) {
      URLRequest* request = requests_in_flight.at(i).get();
      throughput_analyzer.NotifyRequestCompleted(*request);
    }

    base::RunLoop().RunUntilIdle();

    // Only one observation should be taken since two requests overlap.
    if (test.expect_throughput_observation) {
      EXPECT_EQ(1, throughput_analyzer.throughput_observations_received());
    } else {
      EXPECT_EQ(0, throughput_analyzer.throughput_observations_received());
    }
  }
}

// Tests if the throughput observation is taken correctly when the start and end
// of network requests overlap, and the minimum number of in flight requests
// when taking an observation is more than 1.
TEST(ThroughputAnalyzerTest, TestThroughputWithMultipleNetworkRequests) {
  std::map<std::string, std::string> variation_params;
  variation_params["throughput_min_requests_in_flight"] = "3";
  NetworkQualityEstimatorParams params(variation_params);
  TestThroughputAnalyzer throughput_analyzer(&params);
  TestDelegate test_delegate;
  TestURLRequestContext context;
  throughput_analyzer.AddIPAddressResolution(&context);

  EXPECT_EQ(0, throughput_analyzer.throughput_observations_received());

  std::unique_ptr<URLRequest> request_1 = context.CreateRequest(
      GURL("http://example.com/echo.html"), DEFAULT_PRIORITY, &test_delegate,
      TRAFFIC_ANNOTATION_FOR_TESTS);
  std::unique_ptr<URLRequest> request_2 = context.CreateRequest(
      GURL("http://example.com/echo.html"), DEFAULT_PRIORITY, &test_delegate,
      TRAFFIC_ANNOTATION_FOR_TESTS);
  std::unique_ptr<URLRequest> request_3 = context.CreateRequest(
      GURL("http://example.com/echo.html"), DEFAULT_PRIORITY, &test_delegate,
      TRAFFIC_ANNOTATION_FOR_TESTS);
  std::unique_ptr<URLRequest> request_4 = context.CreateRequest(
      GURL("http://example.com/echo.html"), DEFAULT_PRIORITY, &test_delegate,
      TRAFFIC_ANNOTATION_FOR_TESTS);

  request_1->Start();
  request_2->Start();
  request_3->Start();
  request_4->Start();

  base::RunLoop().Run();

  EXPECT_EQ(0, throughput_analyzer.throughput_observations_received());

  throughput_analyzer.NotifyStartTransaction(*(request_1.get()));
  throughput_analyzer.NotifyStartTransaction(*(request_2.get()));

  const size_t increment_bits = 100 * 1000 * 8;

  // Increment the bytes received count to emulate the bytes received for
  // |request_1| and |request_2|.
  throughput_analyzer.IncrementBitsReceived(increment_bits);

  throughput_analyzer.NotifyRequestCompleted(*(request_1.get()));
  base::RunLoop().RunUntilIdle();
  // No observation should be taken since only 1 request is in flight.
  EXPECT_EQ(0, throughput_analyzer.throughput_observations_received());

  throughput_analyzer.NotifyStartTransaction(*(request_3.get()));
  throughput_analyzer.NotifyStartTransaction(*(request_4.get()));
  EXPECT_EQ(0, throughput_analyzer.throughput_observations_received());

  // 3 requests are in flight which is at least as many as the minimum number of
  // in flight requests required. An observation should be taken.
  throughput_analyzer.IncrementBitsReceived(increment_bits);

  // Only one observation should be taken since two requests overlap.
  throughput_analyzer.NotifyRequestCompleted(*(request_2.get()));
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1, throughput_analyzer.throughput_observations_received());
  throughput_analyzer.NotifyRequestCompleted(*(request_3.get()));
  throughput_analyzer.NotifyRequestCompleted(*(request_4.get()));
  EXPECT_EQ(1, throughput_analyzer.throughput_observations_received());
}

}  // namespace

}  // namespace nqe

}  // namespace net

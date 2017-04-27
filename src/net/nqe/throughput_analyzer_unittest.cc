// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/throughput_analyzer.h"

#include <stdint.h>

#include <deque>
#include <memory>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/url_util.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace nqe {

namespace {

class TestThroughputAnalyzer : public internal::ThroughputAnalyzer {
 public:
  TestThroughputAnalyzer()
      : internal::ThroughputAnalyzer(
            base::ThreadTaskRunnerHandle::Get(),
            base::Bind(
                &TestThroughputAnalyzer::OnNewThroughputObservationAvailable,
                base::Unretained(this)),
            false,
            false),
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

  using internal::ThroughputAnalyzer::disable_throughput_measurements;

 private:
  int throughput_observations_received_;

  int64_t bits_received_;

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
    TestThroughputAnalyzer throughput_analyzer;

    TestDelegate test_delegate;
    TestURLRequestContext context;

    ASSERT_FALSE(throughput_analyzer.disable_throughput_measurements());
    std::deque<std::unique_ptr<URLRequest>> requests;

    // Start more requests than the maximum number of requests that can be held
    // in the memory.
    const std::string url = test.use_local_requests
                                ? "http://127.0.0.1/test.html"
                                : "http://example.com/test.html";
    for (size_t i = 0; i < 1000; ++i) {
      std::unique_ptr<URLRequest> request(
          context.CreateRequest(GURL(url), DEFAULT_PRIORITY, &test_delegate,
                                TRAFFIC_ANNOTATION_FOR_TESTS));
      ASSERT_EQ(test.use_local_requests, IsLocalhost(request->url().host()));

      throughput_analyzer.NotifyStartTransaction(*(request.get()));
      requests.push_back(std::move(request));
    }
    // Too many local requests should cause the |throughput_analyzer| to disable
    // throughput measurements.
    EXPECT_EQ(test.use_local_requests,
              throughput_analyzer.disable_throughput_measurements());
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
    TestThroughputAnalyzer throughput_analyzer;

    TestDelegate test_delegate;
    TestURLRequestContext context;

    std::unique_ptr<URLRequest> request_local;

    std::unique_ptr<URLRequest> request_not_local(context.CreateRequest(
        GURL("http://example.com/echo.html"), DEFAULT_PRIORITY, &test_delegate,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    request_not_local->Start();

    if (test.start_local_request) {
      request_local = context.CreateRequest(GURL("http://localhost/echo.html"),
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
    throughput_analyzer.NotifyStartTransaction(*request_not_local);

    if (test.local_request_completes_first) {
      ASSERT_TRUE(test.start_local_request);
      throughput_analyzer.NotifyRequestCompleted(*request_local);
    }

    // Increment the bytes received count to emulate the bytes received for
    // |request_local| and |request_not_local|.
    throughput_analyzer.IncrementBitsReceived(100 * 1000 * 8);

    throughput_analyzer.NotifyRequestCompleted(*request_not_local);
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
    int64_t increment_bits;
    bool expect_throughput_observation;
  } tests[] = {
      {
          100 * 1000 * 8, true,
      },
      {
          1, false,
      },
  };

  for (const auto& test : tests) {
    // Localhost requests are not allowed for estimation purposes.
    TestThroughputAnalyzer throughput_analyzer;
    TestDelegate test_delegate;
    TestURLRequestContext context;

    EXPECT_EQ(0, throughput_analyzer.throughput_observations_received());

    std::unique_ptr<URLRequest> request_network_1 = context.CreateRequest(
        GURL("http://example.com/echo.html"), DEFAULT_PRIORITY, &test_delegate,
        TRAFFIC_ANNOTATION_FOR_TESTS);
    std::unique_ptr<URLRequest> request_network_2 = context.CreateRequest(
        GURL("http://example.com/echo.html"), DEFAULT_PRIORITY, &test_delegate,
        TRAFFIC_ANNOTATION_FOR_TESTS);
    request_network_1->Start();
    request_network_2->Start();

    base::RunLoop().Run();

    EXPECT_LE(0, throughput_analyzer.throughput_observations_received());

    throughput_analyzer.NotifyStartTransaction(*request_network_1);
    throughput_analyzer.NotifyStartTransaction(*request_network_2);

    // Increment the bytes received count to emulate the bytes received for
    // |request_network_1| and |request_network_2|.
    throughput_analyzer.IncrementBitsReceived(test.increment_bits);

    throughput_analyzer.NotifyRequestCompleted(*request_network_1);
    throughput_analyzer.NotifyRequestCompleted(*request_network_2);
    base::RunLoop().RunUntilIdle();

    // Only one observation should be taken since two requests overlap.
    if (test.expect_throughput_observation) {
      EXPECT_EQ(1, throughput_analyzer.throughput_observations_received());
    } else {
      EXPECT_EQ(0, throughput_analyzer.throughput_observations_received());
    }
  }
}

}  // namespace

}  // namespace nqe

}  // namespace net

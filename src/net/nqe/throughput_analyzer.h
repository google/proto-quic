// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_THROUGHPUT_ANALYZER_H_
#define NET_NQE_THROUGHPUT_ANALYZER_H_

#include <stdint.h>

#include "base/callback.h"
#include "base/containers/hash_tables.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/threading/thread_checker.h"
#include "base/time/time.h"
#include "net/base/net_export.h"

namespace {
typedef base::Callback<void(int32_t)> ThroughputObservationCallback;
}

namespace base {
class SingleThreadTaskRunner;
}

namespace net {

class URLRequest;

namespace nqe {

namespace internal {

class NetworkQualityEstimatorParams;

// Makes throughput observations. Polls NetworkActivityMonitor
// (TrafficStats on Android) to count number of bits received over throughput
// observation windows in accordance with the following rules:
// (1) A new window of observation begins any time a URL request header is
//     about to be sent, or a request completes or is destroyed.
// (2) A request is "active" if its headers are sent, but it hasn't completed,
//     and "local" if destined to local host. If at any time during a
//     throughput observation window there is an active, local request, the
//     window is discarded.
// (3) If less than 32KB is received over the network during a window of
//     observation, that window is discarded.
class NET_EXPORT_PRIVATE ThroughputAnalyzer {
 public:
  // |throughput_observation_callback| is called on the |task_runner| when
  // |this| has a new throughput observation.
  // |use_local_host_requests_for_tests| should only be true when testing
  // against local HTTP server and allows the requests to local host to be
  // used for network quality estimation. |use_smaller_responses_for_tests|
  // should only be true when testing, and allows the responses smaller than
  // |kMinTransferSizeInBits| or shorter than
  // |kMinRequestDurationMicroseconds| to be used for network quality
  // estimation.
  // Virtualized for testing.
  ThroughputAnalyzer(
      const NetworkQualityEstimatorParams* params,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      ThroughputObservationCallback throughput_observation_callback,
      bool use_local_host_requests_for_tests,
      bool use_smaller_responses_for_tests);
  virtual ~ThroughputAnalyzer();

  // Notifies |this| that the headers of |request| are about to be sent.
  void NotifyStartTransaction(const URLRequest& request);

  // Notifies |this| that |request| has completed.
  void NotifyRequestCompleted(const URLRequest& request);

  // Notifies |this| of a change in connection type.
  void OnConnectionTypeChanged();

  // |use_localhost_requests| should only be true when testing against local
  // HTTP server and allows the requests to local host to be used for network
  // quality estimation.
  void SetUseLocalHostRequestsForTesting(bool use_localhost_requests);

  // |use_smaller_responses_for_tests| should only be true when testing, and
  // allows the responses smaller than |kMinTransferSizeInBits| or shorter than
  // |kMinRequestDurationMicroseconds| to be used for network quality
  // estimation.
  void SetUseSmallResponsesForTesting(bool use_small_responses);

 protected:
  // Exposed for testing.
  bool disable_throughput_measurements() const {
    return disable_throughput_measurements_;
  }

  // Returns the number of bits received by Chromium so far. The count may not
  // start from zero, so the caller should only look at difference from a prior
  // call. The count is obtained by polling TrafficStats on Android, and
  // net::NetworkActivityMonitor on all other platforms. Virtualized for
  // testing.
  virtual int64_t GetBitsReceived() const;

 private:
  friend class TestThroughputAnalyzer;

  typedef base::hash_set<const URLRequest*> Requests;

  // Returns true if downstream throughput can be recorded. In that case,
  // |downstream_kbps| is set to the computed downstream throughput (in
  // kilobits per second). If a downstream throughput observation is taken,
  // then the throughput observation window is reset so as to continue
  // tracking throughput. A throughput observation can be taken only if the
  // time-window is currently active, and enough bytes have accumulated in
  // that window. |downstream_kbps| should not be null.
  bool MaybeGetThroughputObservation(int32_t* downstream_kbps);

  // Starts the throughput observation window that keeps track of network
  // bytes if the following conditions are true:
  // (i) All active requests are non-local;
  // (ii) There is at least one active, non-local request; and,
  // (iii) The throughput observation window is not already tracking
  // throughput. The window is started by setting the |start_| and
  // |bits_received_|.
  void MaybeStartThroughputObservationWindow();

  // EndThroughputObservationWindow ends the throughput observation window.
  void EndThroughputObservationWindow();

  // Returns true if throughput is currently tracked by a throughput
  // observation window.
  bool IsCurrentlyTrackingThroughput() const;

  // Returns true if the |request| degrades the accuracy of the throughput
  // observation window. A local request or a request that spans a connection
  // change degrades the accuracy of the throughput computation.
  bool DegradesAccuracy(const URLRequest& request) const;

  // Bounds |accuracy_degrading_requests_| and |requests_| to ensure their sizes
  // do not exceed their capacities.
  void BoundRequestsSize();

  const NetworkQualityEstimatorParams* params_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  // Called every time a new throughput observation is available.
  ThroughputObservationCallback throughput_observation_callback_;

  // Time when last connection change was observed.
  base::TimeTicks last_connection_change_;

  // Start time of the current throughput observation window. Set to null if
  // the window is not currently active.
  base::TimeTicks window_start_time_;

  // Number of bits received prior to |start_| as reported by
  // NetworkActivityMonitor.
  int64_t bits_received_at_window_start_;

  // Container that holds active requests that reduce the accuracy of
  // throughput computation. These requests are not used in throughput
  // computation.
  Requests accuracy_degrading_requests_;

  // Container that holds active requests that do not reduce the accuracy of
  // throughput computation. These requests are used in throughput computation.
  Requests requests_;

  // If true, then |this| throughput analyzer stops tracking the throughput
  // observations until Chromium is restarted. This may happen if the throughput
  // analyzer has lost track of the requests that degrade throughput computation
  // accuracy.
  bool disable_throughput_measurements_;

  // Determines if the requests to local host can be used in estimating the
  // network quality. Set to true only for tests.
  bool use_localhost_requests_for_tests_;

  // Determines if the responses smaller than |kMinTransferSizeInBits|
  // or shorter than |kMinTransferSizeInBits| can be used in estimating the
  // network quality. Set to true only for tests.
  bool use_small_responses_for_tests_;

  base::ThreadChecker thread_checker_;

  DISALLOW_COPY_AND_ASSIGN(ThroughputAnalyzer);
};

}  // namespace internal

}  // namespace nqe

}  // namespace net

#endif  // NET_NQE_THROUGHPUT_ANALYZER_H_

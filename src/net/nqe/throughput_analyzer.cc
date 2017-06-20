// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/throughput_analyzer.h"

#include <cmath>

#include "base/location.h"
#include "base/single_thread_task_runner.h"
#include "net/base/host_port_pair.h"
#include "net/base/network_activity_monitor.h"
#include "net/base/url_util.h"
#include "net/nqe/network_quality_estimator_params.h"
#include "net/nqe/network_quality_estimator_util.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"

namespace net {

class HostResolver;

namespace {

// Maximum number of accuracy degrading requests, and requests that do not
// degrade accuracy held in the memory.
static const size_t kMaxRequestsSize = 300;

// Tiny transfer sizes may give inaccurate throughput results.
// Minimum size of the transfer over which the throughput is computed.
static const int kMinTransferSizeInBits = 32 * 8 * 1000;

}  // namespace

namespace nqe {

namespace internal {

ThroughputAnalyzer::ThroughputAnalyzer(
    const NetworkQualityEstimatorParams* params,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    ThroughputObservationCallback throughput_observation_callback,
    bool use_local_host_requests_for_tests,
    bool use_smaller_responses_for_tests,
    const NetLogWithSource& net_log)
    : params_(params),
      task_runner_(task_runner),
      throughput_observation_callback_(throughput_observation_callback),
      last_connection_change_(base::TimeTicks::Now()),
      window_start_time_(base::TimeTicks()),
      bits_received_at_window_start_(0),
      disable_throughput_measurements_(false),
      use_localhost_requests_for_tests_(use_local_host_requests_for_tests),
      use_small_responses_for_tests_(use_smaller_responses_for_tests),
      net_log_(net_log) {
  DCHECK(params_);
  DCHECK(task_runner_);
  DCHECK(!IsCurrentlyTrackingThroughput());
}

ThroughputAnalyzer::~ThroughputAnalyzer() {
  DCHECK(thread_checker_.CalledOnValidThread());
}

void ThroughputAnalyzer::MaybeStartThroughputObservationWindow() {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (disable_throughput_measurements_)
    return;

  // Throughput observation window can be started only if no accuracy degrading
  // requests are currently active, the observation window is not already
  // started, and there is at least one active request that does not degrade
  // throughput computation accuracy.
  if (accuracy_degrading_requests_.size() > 0 ||
      IsCurrentlyTrackingThroughput() ||
      requests_.size() < params_->throughput_min_requests_in_flight()) {
    return;
  }
  window_start_time_ = base::TimeTicks::Now();
  bits_received_at_window_start_ = GetBitsReceived();
}

void ThroughputAnalyzer::EndThroughputObservationWindow() {
  DCHECK(thread_checker_.CalledOnValidThread());

  // Mark the throughput observation window as stopped by resetting the window
  // parameters.
  window_start_time_ = base::TimeTicks();
  bits_received_at_window_start_ = 0;
}

bool ThroughputAnalyzer::IsCurrentlyTrackingThroughput() const {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (window_start_time_.is_null())
    return false;

  // If the throughput observation window is running, then at least one request
  // that does not degrade throughput computation accuracy should be active.
  DCHECK_GT(requests_.size(), 0U);

  // If the throughput observation window is running, then no accuracy degrading
  // requests should be currently active.
  DCHECK_EQ(0U, accuracy_degrading_requests_.size());

  DCHECK_LE(params_->throughput_min_requests_in_flight(), requests_.size());

  return true;
}

void ThroughputAnalyzer::NotifyStartTransaction(const URLRequest& request) {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (disable_throughput_measurements_)
    return;

  const bool degrades_accuracy = DegradesAccuracy(request);
  if (degrades_accuracy) {
    accuracy_degrading_requests_.insert(&request);

    BoundRequestsSize();
    if (disable_throughput_measurements_)
      return;

    // Call EndThroughputObservationWindow since observations cannot be
    // recorded in the presence of requests that degrade throughput computation
    // accuracy.
    EndThroughputObservationWindow();
    DCHECK(!IsCurrentlyTrackingThroughput());
    return;
  }

  requests_.insert(&request);
  BoundRequestsSize();
  MaybeStartThroughputObservationWindow();
}

void ThroughputAnalyzer::NotifyRequestCompleted(const URLRequest& request) {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (disable_throughput_measurements_)
    return;

  // Return early if the |request| is not present in the collections of
  // requests. This may happen when a completed request is later destroyed.
  if (requests_.find(&request) == requests_.end() &&
      accuracy_degrading_requests_.find(&request) ==
          accuracy_degrading_requests_.end()) {
    return;
  }

  int32_t downstream_kbps;
  if (MaybeGetThroughputObservation(&downstream_kbps)) {
    // Notify the provided callback.
    task_runner_->PostTask(
        FROM_HERE,
        base::Bind(throughput_observation_callback_, downstream_kbps));
  }

  // Try to remove the request from either |accuracy_degrading_requests_| or
  // |requests_|, since it is no longer active.
  if (accuracy_degrading_requests_.erase(&request) == 1u) {
    // |request| cannot be in both |accuracy_degrading_requests_| and
    // |requests_| at the same time.
    DCHECK(requests_.end() == requests_.find(&request));

    // If a request that degraded the accuracy of throughput computation has
    // completed, then it may be possible to start the tracking window.
    MaybeStartThroughputObservationWindow();
    return;
  }

  if (requests_.erase(&request) == 1u) {
    // If there is no network activity, stop tracking throughput to prevent
    // recording of any observations.
    if (requests_.size() < params_->throughput_min_requests_in_flight())
      EndThroughputObservationWindow();
    return;
  }
  // |request| must be either in |accuracy_degrading_requests_| or |requests_|.
  NOTREACHED();
}

bool ThroughputAnalyzer::MaybeGetThroughputObservation(
    int32_t* downstream_kbps) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(downstream_kbps);

  if (disable_throughput_measurements_)
    return false;

  // Return early if the window that records downstream throughput is currently
  // inactive because throughput observations can be taken only when the window
  // is active.
  if (!IsCurrentlyTrackingThroughput())
    return false;

  DCHECK_GT(requests_.size(), 0U);
  DCHECK_EQ(0U, accuracy_degrading_requests_.size());

  base::TimeTicks now = base::TimeTicks::Now();

  int64_t bits_received = GetBitsReceived() - bits_received_at_window_start_;
  DCHECK_LE(window_start_time_, now);
  base::TimeDelta duration = now - window_start_time_;

  // Ignore tiny/short transfers, which will not produce accurate rates. Skip
  // the checks if |use_small_responses_| is true.
  if (!use_small_responses_for_tests_ && bits_received < kMinTransferSizeInBits)
    return false;

  double downstream_kbps_double =
      (bits_received * 1.0f) / duration.InMillisecondsF();
  // Round-up |downstream_kbps_double|.
  *downstream_kbps = static_cast<int64_t>(std::ceil(downstream_kbps_double));

  // Stop the observation window since a throughput measurement has been taken.
  EndThroughputObservationWindow();
  DCHECK(!IsCurrentlyTrackingThroughput());

  // Maybe start the throughput observation window again so that another
  // throughput measurement can be taken.
  MaybeStartThroughputObservationWindow();
  return true;
}

void ThroughputAnalyzer::OnConnectionTypeChanged() {
  DCHECK(thread_checker_.CalledOnValidThread());

  // All the requests that were previously not degrading the througpput
  // computation are now spanning a connection change event. These requests
  // would now degrade the throughput computation accuracy. So, move them to
  // |accuracy_degrading_requests_|.
  for (const URLRequest* request : requests_)
    accuracy_degrading_requests_.insert(request);
  requests_.clear();
  BoundRequestsSize();
  EndThroughputObservationWindow();

  last_connection_change_ = base::TimeTicks::Now();
}

void ThroughputAnalyzer::SetUseLocalHostRequestsForTesting(
    bool use_localhost_requests) {
  DCHECK(thread_checker_.CalledOnValidThread());
  use_localhost_requests_for_tests_ = use_localhost_requests;
}

void ThroughputAnalyzer::SetUseSmallResponsesForTesting(
    bool use_small_responses) {
  DCHECK(thread_checker_.CalledOnValidThread());
  use_small_responses_for_tests_ = use_small_responses;
}

int64_t ThroughputAnalyzer::GetBitsReceived() const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return NetworkActivityMonitor::GetInstance()->GetBytesReceived() * 8;
}

bool ThroughputAnalyzer::DegradesAccuracy(const URLRequest& request) const {
  DCHECK(thread_checker_.CalledOnValidThread());

  bool private_network_request = nqe::internal::IsPrivateHost(
      request.context()->host_resolver(),
      HostPortPair(request.url().host(), request.url().EffectiveIntPort()),
      net_log_);

  return !(use_localhost_requests_for_tests_ || !private_network_request) ||
         request.creation_time() < last_connection_change_;
}

void ThroughputAnalyzer::BoundRequestsSize() {
  if (accuracy_degrading_requests_.size() > kMaxRequestsSize) {
    // Clear |accuracy_degrading_requests_| since its size has exceeded its
    // capacity.
    accuracy_degrading_requests_.clear();
    // Disable throughput measurements since |this| has lost track of the
    // accuracy degrading requests.
    disable_throughput_measurements_ = true;

    // Reset other variables related to tracking since the tracking is now
    // disabled.
    EndThroughputObservationWindow();
    DCHECK(!IsCurrentlyTrackingThroughput());
    requests_.clear();

    // TODO(tbansal): crbug.com/609174 Add UMA to record how frequently this
    // happens.
  }

  if (requests_.size() > kMaxRequestsSize) {
    // Clear |requests_| since its size has exceeded its capacity.
    EndThroughputObservationWindow();
    DCHECK(!IsCurrentlyTrackingThroughput());
    requests_.clear();

    // TODO(tbansal): crbug.com/609174 Add UMA to record how frequently this
    // happens.
  }
}

}  // namespace internal

}  // namespace nqe

}  // namespace net

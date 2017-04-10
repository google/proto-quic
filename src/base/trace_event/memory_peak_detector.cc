// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/memory_peak_detector.h"

#include <stdint.h>

#include "base/bind.h"
#include "base/logging.h"
#include "base/threading/sequenced_task_runner_handle.h"
#include "base/time/time.h"
#include "base/trace_event/memory_dump_provider_info.h"

namespace base {
namespace trace_event {

// static
MemoryPeakDetector* MemoryPeakDetector::GetInstance() {
  static MemoryPeakDetector* instance = new MemoryPeakDetector();
  return instance;
}

MemoryPeakDetector::MemoryPeakDetector()
    : generation_(0),
      state_(NOT_INITIALIZED),
      polling_interval_ms_(0),
      poll_tasks_count_for_testing_(0) {}

MemoryPeakDetector::~MemoryPeakDetector() {
  // This is hit only in tests, in which case the test is expected to TearDown()
  // cleanly and not leave the peak detector running.
  DCHECK_EQ(NOT_INITIALIZED, state_);
}

void MemoryPeakDetector::Setup(
    const GetDumpProvidersFunction& get_dump_providers_function,
    const scoped_refptr<SequencedTaskRunner>& task_runner,
    const OnPeakDetectedCallback& on_peak_detected_callback) {
  DCHECK(!get_dump_providers_function.is_null());
  DCHECK(task_runner);
  DCHECK(!on_peak_detected_callback.is_null());
  DCHECK(state_ == NOT_INITIALIZED || state_ == DISABLED);
  DCHECK(dump_providers_.empty());
  get_dump_providers_function_ = get_dump_providers_function;
  task_runner_ = task_runner;
  on_peak_detected_callback_ = on_peak_detected_callback;
  state_ = DISABLED;
}

void MemoryPeakDetector::TearDown() {
  if (task_runner_) {
    task_runner_->PostTask(
        FROM_HERE,
        Bind(&MemoryPeakDetector::TearDownInternal, Unretained(this)));
  }
  task_runner_ = nullptr;
}

void MemoryPeakDetector::Start() {
  task_runner_->PostTask(
      FROM_HERE, Bind(&MemoryPeakDetector::StartInternal, Unretained(this)));
}

void MemoryPeakDetector::Stop() {
  task_runner_->PostTask(
      FROM_HERE, Bind(&MemoryPeakDetector::StopInternal, Unretained(this)));
}

void MemoryPeakDetector::NotifyMemoryDumpProvidersChanged() {
  // It is possible to call this before the first Setup() call, in which case
  // we want to just make this a noop. The next Start() will fetch the MDP list.
  if (!task_runner_)
    return;
  task_runner_->PostTask(
      FROM_HERE,
      Bind(&MemoryPeakDetector::ReloadDumpProvidersAndStartPollingIfNeeded,
           Unretained(this)));
}

void MemoryPeakDetector::StartInternal() {
  DCHECK_EQ(DISABLED, state_);
  state_ = ENABLED;
  polling_interval_ms_ = 1;  // TODO(primiano): temporary until next CL.

  // If there are any dump providers available, NotifyMemoryDumpProvidersChanged
  // will fetch them and start the polling. Otherwise this will remain in the
  // ENABLED state and the actual polling will start on the next call to
  // ReloadDumpProvidersAndStartPollingIfNeeded().
  // Depending on the sandbox model, it is possible that no polling-capable dump
  // providers will be ever available.
  ReloadDumpProvidersAndStartPollingIfNeeded();
}

void MemoryPeakDetector::StopInternal() {
  DCHECK_NE(NOT_INITIALIZED, state_);
  state_ = DISABLED;
  ++generation_;
  dump_providers_.clear();
}

void MemoryPeakDetector::TearDownInternal() {
  StopInternal();
  get_dump_providers_function_.Reset();
  on_peak_detected_callback_.Reset();
  state_ = NOT_INITIALIZED;
}

void MemoryPeakDetector::ReloadDumpProvidersAndStartPollingIfNeeded() {
  if (state_ == DISABLED || state_ == NOT_INITIALIZED)
    return;  // Start() will re-fetch the MDP list later.

  DCHECK((state_ == RUNNING && !dump_providers_.empty()) ||
         (state_ == ENABLED && dump_providers_.empty()));

  dump_providers_.clear();

  // This is really MemoryDumpManager::GetDumpProvidersForPolling, % testing.
  get_dump_providers_function_.Run(&dump_providers_);

  if (state_ == ENABLED && !dump_providers_.empty()) {
    // It's now time to start polling for realz.
    state_ = RUNNING;
    task_runner_->PostTask(FROM_HERE,
                           Bind(&MemoryPeakDetector::PollMemoryAndDetectPeak,
                                Unretained(this), ++generation_));
  } else if (state_ == RUNNING && dump_providers_.empty()) {
    // Will cause the next PollMemoryAndDetectPeak() task to early return.
    state_ = ENABLED;
    ++generation_;
  }
}

void MemoryPeakDetector::PollMemoryAndDetectPeak(uint32_t expected_generation) {
  if (state_ != RUNNING || expected_generation != generation_)
    return;

  // We should never end up in a situation where state_ == RUNNING but all dump
  // providers are gone.
  DCHECK(!dump_providers_.empty());

  poll_tasks_count_for_testing_++;
  uint64_t memory_total = 0;
  for (const scoped_refptr<MemoryDumpProviderInfo>& mdp_info :
       dump_providers_) {
    DCHECK(mdp_info->options.is_fast_polling_supported);
    uint64_t value = 0;
    mdp_info->dump_provider->PollFastMemoryTotal(&value);
    memory_total += value;
  }
  ignore_result(memory_total);  // TODO(primiano): temporary until next CL.

  // TODO(primiano): Move actual peak detection logic from the
  // MemoryDumpScheduler in next CLs.

  SequencedTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE,
      Bind(&MemoryPeakDetector::PollMemoryAndDetectPeak, Unretained(this),
           expected_generation),
      TimeDelta::FromMilliseconds(polling_interval_ms_));
}

}  // namespace trace_event
}  // namespace base

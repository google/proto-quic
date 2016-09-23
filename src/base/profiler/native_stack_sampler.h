// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_PROFILER_NATIVE_STACK_SAMPLER_H_
#define BASE_PROFILER_NATIVE_STACK_SAMPLER_H_

#include <memory>

#include "base/base_export.h"
#include "base/macros.h"
#include "base/profiler/stack_sampling_profiler.h"
#include "base/threading/platform_thread.h"

namespace base {

class NativeStackSamplerTestDelegate;

// NativeStackSampler is an implementation detail of StackSamplingProfiler. It
// abstracts the native implementation required to record a stack sample for a
// given thread.
class NativeStackSampler {
 public:
  virtual ~NativeStackSampler();

  // Creates a stack sampler that records samples for |thread_handle|. Returns
  // null if this platform does not support stack sampling.
  static std::unique_ptr<NativeStackSampler> Create(
      PlatformThreadId thread_id,
      NativeStackSamplerTestDelegate* test_delegate);

  // The following functions are all called on the SamplingThread (not the
  // thread being sampled).

  // Notifies the sampler that we're starting to record a new profile. Modules
  // shared across samples in the profile should be recorded in |modules|.
  virtual void ProfileRecordingStarting(
      std::vector<StackSamplingProfiler::Module>* modules) = 0;

  // Records a stack sample to |sample|.
  virtual void RecordStackSample(StackSamplingProfiler::Sample* sample) = 0;

  // Notifies the sampler that we've stopped recording the current
  // profile.
  virtual void ProfileRecordingStopped() = 0;

 protected:
  NativeStackSampler();

 private:
  DISALLOW_COPY_AND_ASSIGN(NativeStackSampler);
};

// NativeStackSamplerTestDelegate provides seams for test code to execute during
// stack collection.
class BASE_EXPORT NativeStackSamplerTestDelegate {
 public:
  virtual ~NativeStackSamplerTestDelegate();

  // Called after copying the stack and resuming the target thread, but prior to
  // walking the stack. Invoked on the SamplingThread.
  virtual void OnPreStackWalk() = 0;

 protected:
  NativeStackSamplerTestDelegate();

 private:
  DISALLOW_COPY_AND_ASSIGN(NativeStackSamplerTestDelegate);
};

}  // namespace base

#endif  // BASE_PROFILER_NATIVE_STACK_SAMPLER_H_


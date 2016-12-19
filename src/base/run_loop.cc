// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/run_loop.h"

#include "base/bind.h"
#include "base/tracked_objects.h"
#include "build/build_config.h"

namespace base {

RunLoop::RunLoop()
    : loop_(MessageLoop::current()),
      previous_run_loop_(NULL),
      run_depth_(0),
      run_called_(false),
      quit_called_(false),
      running_(false),
      quit_when_idle_received_(false),
      weak_factory_(this) {
  DCHECK(loop_);
}

RunLoop::~RunLoop() {
}

void RunLoop::Run() {
  DCHECK(thread_checker_.CalledOnValidThread());
  if (!BeforeRun())
    return;

  // Use task stopwatch to exclude the loop run time from the current task, if
  // any.
  tracked_objects::TaskStopwatch stopwatch;
  stopwatch.Start();
  loop_->RunHandler();
  stopwatch.Stop();

  AfterRun();
}

void RunLoop::RunUntilIdle() {
  quit_when_idle_received_ = true;
  Run();
}

void RunLoop::Quit() {
  DCHECK(thread_checker_.CalledOnValidThread());
  quit_called_ = true;
  if (running_ && loop_->run_loop_ == this) {
    // This is the inner-most RunLoop, so quit now.
    loop_->QuitNow();
  }
}

void RunLoop::QuitWhenIdle() {
  DCHECK(thread_checker_.CalledOnValidThread());
  quit_when_idle_received_ = true;
}

base::Closure RunLoop::QuitClosure() {
  return base::Bind(&RunLoop::Quit, weak_factory_.GetWeakPtr());
}

base::Closure RunLoop::QuitWhenIdleClosure() {
  return base::Bind(&RunLoop::QuitWhenIdle, weak_factory_.GetWeakPtr());
}

bool RunLoop::BeforeRun() {
  DCHECK(!run_called_);
  run_called_ = true;

  // Allow Quit to be called before Run.
  if (quit_called_)
    return false;

  // Push RunLoop stack:
  previous_run_loop_ = loop_->run_loop_;
  run_depth_ = previous_run_loop_? previous_run_loop_->run_depth_ + 1 : 1;
  loop_->run_loop_ = this;

  if (run_depth_ > 1)
    loop_->NotifyBeginNestedLoop();

  running_ = true;
  return true;
}

void RunLoop::AfterRun() {
  running_ = false;

  // Pop RunLoop stack:
  loop_->run_loop_ = previous_run_loop_;

  // Execute deferred QuitNow, if any:
  if (previous_run_loop_ && previous_run_loop_->quit_called_)
    loop_->QuitNow();
}

}  // namespace base

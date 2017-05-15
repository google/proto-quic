// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/run_loop.h"

#include <stack>

#include "base/bind.h"
#include "base/lazy_instance.h"
#include "base/observer_list.h"
#include "base/threading/thread_local_storage.h"
#include "base/tracked_objects.h"
#include "build/build_config.h"

namespace base {

namespace {

class ThreadLocalRunLoopState {
 public:
  // A vector-based stack is more memory efficient than the default deque-based
  // stack as the active RunLoop stack isn't expected to ever have more than a
  // few entries.
  using RunLoopStack = std::stack<RunLoop*, std::vector<RunLoop*>>;

  ThreadLocalRunLoopState()
      : slot_(&ThreadLocalRunLoopState::OnTLSDestruction) {}

  ~ThreadLocalRunLoopState() = delete;

  RunLoopStack& GetActiveRunLoops() {
    return GetOrCreateInternalState()->active_run_loops;
  }

  ObserverList<RunLoop::NestingObserver>& GetNestingObservers() {
    InternalState* state = GetOrCreateInternalState();
    CHECK(state->allow_nesting);
    return state->nesting_observers;
  }

  bool IsNestingAllowed() { return GetOrCreateInternalState()->allow_nesting; }

  void DisallowNesting() { GetOrCreateInternalState()->allow_nesting = false; }

  void Reset() {
    InternalState* state = static_cast<InternalState*>(slot_.Get());
    if (state) {
      slot_.Set(nullptr);
      delete state;
    }
  }

 private:
  struct InternalState {
    bool allow_nesting = true;
    RunLoopStack active_run_loops;
    ObserverList<RunLoop::NestingObserver> nesting_observers;
  };

  static void OnTLSDestruction(void* internal_state) {
    delete static_cast<InternalState*>(internal_state);
  }

  InternalState* GetOrCreateInternalState() {
    InternalState* state = static_cast<InternalState*>(slot_.Get());
    if (!state) {
      state = new InternalState;
      slot_.Set(static_cast<void*>(state));
    }
    return state;
  }

  ThreadLocalStorage::Slot slot_;

  DISALLOW_COPY_AND_ASSIGN(ThreadLocalRunLoopState);
};

LazyInstance<ThreadLocalRunLoopState>::Leaky tls_run_loop_state =
    LAZY_INSTANCE_INITIALIZER;

}  // namespace

RunLoop::RunLoop()
    : loop_(MessageLoop::current()),
      weak_factory_(this) {
  DCHECK(loop_);
}

RunLoop::~RunLoop() {
  // TODO(gab): Fix bad usage and enable this check, http://crbug.com/715235.
  // DCHECK(thread_checker_.CalledOnValidThread());
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
  DCHECK(thread_checker_.CalledOnValidThread());

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
  // TODO(gab): Fix bad usage and enable this check, http://crbug.com/715235.
  // DCHECK(thread_checker_.CalledOnValidThread());
  return base::Bind(&RunLoop::Quit, weak_factory_.GetWeakPtr());
}

base::Closure RunLoop::QuitWhenIdleClosure() {
  // TODO(gab): Fix bad usage and enable this check, http://crbug.com/715235.
  // DCHECK(thread_checker_.CalledOnValidThread());
  return base::Bind(&RunLoop::QuitWhenIdle, weak_factory_.GetWeakPtr());
}

// static
void RunLoop::ResetTLSState() {
  tls_run_loop_state.Get().Reset();
}

// static
bool RunLoop::IsRunningOnCurrentThread() {
  return !tls_run_loop_state.Get().GetActiveRunLoops().empty();
}

// static
bool RunLoop::IsNestedOnCurrentThread() {
  return tls_run_loop_state.Get().GetActiveRunLoops().size() > 1;
}

// static
void RunLoop::AddNestingObserverOnCurrentThread(NestingObserver* observer) {
  tls_run_loop_state.Get().GetNestingObservers().AddObserver(observer);
}

// static
void RunLoop::RemoveNestingObserverOnCurrentThread(NestingObserver* observer) {
  tls_run_loop_state.Get().GetNestingObservers().RemoveObserver(observer);
}

// static
bool RunLoop::IsNestingAllowedOnCurrentThread() {
  return tls_run_loop_state.Get().IsNestingAllowed();
}

// static
void RunLoop::DisallowNestingOnCurrentThread() {
  tls_run_loop_state.Get().DisallowNesting();
}

bool RunLoop::BeforeRun() {
  DCHECK(thread_checker_.CalledOnValidThread());

  DCHECK(!run_called_);
  run_called_ = true;

  // Allow Quit to be called before Run.
  if (quit_called_)
    return false;

  auto& active_run_loops = tls_run_loop_state.Get().GetActiveRunLoops();
  active_run_loops.push(this);

  const bool is_nested = active_run_loops.size() > 1;

  // TODO(gab): Break the inter-dependency between MessageLoop and RunLoop
  // further. http://crbug.com/703346
  loop_->run_loop_ = this;
  loop_->is_nested_ = is_nested;

  if (is_nested) {
    CHECK(tls_run_loop_state.Get().IsNestingAllowed());
    for (auto& observer : tls_run_loop_state.Get().GetNestingObservers())
      observer.OnBeginNestedRunLoop();
  }

  running_ = true;
  return true;
}

void RunLoop::AfterRun() {
  DCHECK(thread_checker_.CalledOnValidThread());

  running_ = false;

  auto& active_run_loops = tls_run_loop_state.Get().GetActiveRunLoops();
  DCHECK_EQ(active_run_loops.top(), this);
  active_run_loops.pop();

  RunLoop* previous_run_loop =
      active_run_loops.empty() ? nullptr : active_run_loops.top();
  loop_->run_loop_ = previous_run_loop;
  loop_->is_nested_ = active_run_loops.size() > 1;

  // Execute deferred QuitNow, if any:
  if (previous_run_loop && previous_run_loop->quit_called_)
    loop_->QuitNow();
}

}  // namespace base

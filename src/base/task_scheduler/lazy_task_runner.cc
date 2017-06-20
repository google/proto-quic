// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/lazy_task_runner.h"

#include <utility>

#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/task_scheduler/post_task.h"

namespace base {
namespace internal {

namespace {
ScopedLazyTaskRunnerListForTesting* g_scoped_lazy_task_runner_list_for_testing =
    nullptr;
}  // namespace

template <typename TaskRunnerType, bool com_sta>
void LazyTaskRunner<TaskRunnerType, com_sta>::Reset() {
  subtle::AtomicWord state = subtle::Acquire_Load(&state_);

  DCHECK_NE(state, kLazyInstanceStateCreating) << "Race: all threads should be "
                                                  "unwound in unittests before "
                                                  "resetting TaskRunners.";

  // Return if no reference is held by this instance.
  if (!state)
    return;

  // Release the reference acquired in Get().
  SequencedTaskRunner* task_runner = reinterpret_cast<TaskRunnerType*>(state);
  task_runner->Release();

  // Clear the state.
  subtle::NoBarrier_Store(&state_, 0);
}

template <>
scoped_refptr<SequencedTaskRunner>
LazyTaskRunner<SequencedTaskRunner, false>::Create() {
  // It is invalid to specify a SingleThreadTaskRunnerThreadMode with a
  // LazySequencedTaskRunner.
  DCHECK_EQ(thread_mode_, SingleThreadTaskRunnerThreadMode::SHARED);

  return CreateSequencedTaskRunnerWithTraits(traits_);
}

template <>
scoped_refptr<SingleThreadTaskRunner>
LazyTaskRunner<SingleThreadTaskRunner, false>::Create() {
  return CreateSingleThreadTaskRunnerWithTraits(traits_, thread_mode_);
}

#if defined(OS_WIN)
template <>
scoped_refptr<SingleThreadTaskRunner>
LazyTaskRunner<SingleThreadTaskRunner, true>::Create() {
  return CreateCOMSTATaskRunnerWithTraits(traits_, thread_mode_);
}
#endif

template <typename TaskRunnerType, bool com_sta>
scoped_refptr<TaskRunnerType> LazyTaskRunner<TaskRunnerType, com_sta>::Get() {
  return make_scoped_refptr(static_cast<TaskRunnerType*>(GetOrCreateLazyPointer(
      &state_,
      [this]() {
        scoped_refptr<TaskRunnerType> task_runner = Create();

        // Acquire a reference to the TaskRunner. The reference will either
        // never be released or be released in Reset(). The reference is not
        // managed by a scoped_refptr because adding a scoped_refptr member to
        // LazyTaskRunner would prevent its static initialization.
        task_runner->AddRef();

        // Reset this instance when the current
        // ScopedLazyTaskRunnerListForTesting is destroyed, if any.
        if (g_scoped_lazy_task_runner_list_for_testing) {
          g_scoped_lazy_task_runner_list_for_testing->AddCallback(
              BindOnce(&LazyTaskRunner<TaskRunnerType, com_sta>::Reset,
                       Unretained(this)));
        }

        return task_runner.get();
      },
      nullptr, nullptr)));
}

template class LazyTaskRunner<SequencedTaskRunner, false>;
template class LazyTaskRunner<SingleThreadTaskRunner, false>;

#if defined(OS_WIN)
template class LazyTaskRunner<SingleThreadTaskRunner, true>;
#endif

ScopedLazyTaskRunnerListForTesting::ScopedLazyTaskRunnerListForTesting() {
  DCHECK(!g_scoped_lazy_task_runner_list_for_testing);
  g_scoped_lazy_task_runner_list_for_testing = this;
}

ScopedLazyTaskRunnerListForTesting::~ScopedLazyTaskRunnerListForTesting() {
  internal::AutoSchedulerLock auto_lock(lock_);
  for (auto& callback : callbacks_)
    std::move(callback).Run();
  g_scoped_lazy_task_runner_list_for_testing = nullptr;
}

void ScopedLazyTaskRunnerListForTesting::AddCallback(OnceClosure callback) {
  internal::AutoSchedulerLock auto_lock(lock_);
  callbacks_.push_back(std::move(callback));
}

}  // namespace internal
}  // namespace base

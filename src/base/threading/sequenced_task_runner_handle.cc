// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/threading/sequenced_task_runner_handle.h"

#include <utility>

#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/sequenced_task_runner.h"
#include "base/thread_task_runner_handle.h"
#include "base/threading/sequenced_worker_pool.h"
#include "base/threading/thread_local.h"

namespace base {

namespace {

base::LazyInstance<base::ThreadLocalPointer<SequencedTaskRunnerHandle>>::Leaky
    lazy_tls_ptr = LAZY_INSTANCE_INITIALIZER;

}  // namespace

// static
scoped_refptr<SequencedTaskRunner> SequencedTaskRunnerHandle::Get() {
  // Return the registered SequencedTaskRunner, if any.
  const SequencedTaskRunnerHandle* handle = lazy_tls_ptr.Pointer()->Get();
  if (handle) {
    // Various modes of setting SequencedTaskRunnerHandle don't combine.
    DCHECK(!base::ThreadTaskRunnerHandle::IsSet());
    DCHECK(!SequencedWorkerPool::GetSequencedTaskRunnerForCurrentThread());
    return handle->task_runner_;
  }

  // Return the SequencedTaskRunner obtained from SequencedWorkerPool, if any.
  scoped_refptr<base::SequencedTaskRunner> task_runner =
      SequencedWorkerPool::GetSequencedTaskRunnerForCurrentThread();
  if (task_runner) {
    DCHECK(!base::ThreadTaskRunnerHandle::IsSet());
    return task_runner;
  }

  // Return the SingleThreadTaskRunner for the current thread otherwise.
  return base::ThreadTaskRunnerHandle::Get();
}

// static
bool SequencedTaskRunnerHandle::IsSet() {
  return lazy_tls_ptr.Pointer()->Get() ||
         SequencedWorkerPool::GetWorkerPoolForCurrentThread() ||
         base::ThreadTaskRunnerHandle::IsSet();
}

SequencedTaskRunnerHandle::SequencedTaskRunnerHandle(
    scoped_refptr<SequencedTaskRunner> task_runner)
    : task_runner_(std::move(task_runner)) {
  DCHECK(task_runner_->RunsTasksOnCurrentThread());
  DCHECK(!SequencedTaskRunnerHandle::IsSet());
  lazy_tls_ptr.Pointer()->Set(this);
}

SequencedTaskRunnerHandle::~SequencedTaskRunnerHandle() {
  DCHECK(task_runner_->RunsTasksOnCurrentThread());
  DCHECK_EQ(lazy_tls_ptr.Pointer()->Get(), this);
  lazy_tls_ptr.Pointer()->Set(nullptr);
}

}  // namespace base

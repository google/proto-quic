// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/threading/sequenced_task_runner_handle.h"

#include <utility>

#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/threading/sequenced_worker_pool.h"
#include "base/threading/thread_local.h"
#include "base/threading/thread_task_runner_handle.h"

namespace base {

namespace {

LazyInstance<ThreadLocalPointer<SequencedTaskRunnerHandle>>::Leaky
    lazy_tls_ptr = LAZY_INSTANCE_INITIALIZER;

}  // namespace

// static
scoped_refptr<SequencedTaskRunner> SequencedTaskRunnerHandle::Get() {
  // Return the registered SingleThreadTaskRunner, if any. This must be at the
  // top so that a SingleThreadTaskRunner has priority over a
  // SequencedTaskRunner (RLZ registers both on the same thread despite that
  // being prevented by DCHECKs).
  // TODO(fdoray): Move this to the bottom once RLZ stops registering a
  // SingleThreadTaskRunner and a SequencedTaskRunner on the same thread.
  // https://crbug.com/618530#c14
  if (ThreadTaskRunnerHandle::IsSet()) {
    // Various modes of setting SequencedTaskRunnerHandle don't combine.
    DCHECK(!lazy_tls_ptr.Pointer()->Get());
    DCHECK(!SequencedWorkerPool::GetSequenceTokenForCurrentThread().IsValid());

    return ThreadTaskRunnerHandle::Get();
  }

  // Return the registered SequencedTaskRunner, if any.
  const SequencedTaskRunnerHandle* handle = lazy_tls_ptr.Pointer()->Get();
  if (handle) {
    // Various modes of setting SequencedTaskRunnerHandle don't combine.
    DCHECK(!SequencedWorkerPool::GetSequenceTokenForCurrentThread().IsValid());

    return handle->task_runner_;
  }

  // If we are on a worker thread for a SequencedBlockingPool that is running a
  // sequenced task, return a SequencedTaskRunner for it.
  scoped_refptr<SequencedWorkerPool> pool =
      SequencedWorkerPool::GetWorkerPoolForCurrentThread();
  DCHECK(pool);
  SequencedWorkerPool::SequenceToken sequence_token =
      SequencedWorkerPool::GetSequenceTokenForCurrentThread();
  DCHECK(sequence_token.IsValid());
  scoped_refptr<SequencedTaskRunner> sequenced_task_runner(
      pool->GetSequencedTaskRunner(sequence_token));
  DCHECK(sequenced_task_runner->RunsTasksOnCurrentThread());
  return sequenced_task_runner;
}

// static
bool SequencedTaskRunnerHandle::IsSet() {
  return lazy_tls_ptr.Pointer()->Get() ||
         SequencedWorkerPool::GetSequenceTokenForCurrentThread().IsValid() ||
         ThreadTaskRunnerHandle::IsSet();
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

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/sequence_checker_impl.h"

#include "base/logging.h"

namespace base {

SequenceCheckerImpl::SequenceCheckerImpl() {
  AutoLock auto_lock(lock_);
  EnsureSequenceTokenAssigned();
}

SequenceCheckerImpl::~SequenceCheckerImpl() = default;

bool SequenceCheckerImpl::CalledOnValidSequence() const {
  AutoLock auto_lock(lock_);
  EnsureSequenceTokenAssigned();

  if (sequence_token_.IsValid())
    return sequence_token_ == SequenceToken::GetForCurrentThread();

  if (sequenced_worker_pool_token_.IsValid()) {
    return sequenced_worker_pool_token_.Equals(
        SequencedWorkerPool::GetSequenceTokenForCurrentThread());
  }

  // SequenceChecker behaves as a ThreadChecker when it is not bound to a valid
  // sequence token.
  return thread_checker_.CalledOnValidThread();
}

void SequenceCheckerImpl::DetachFromSequence() {
  AutoLock auto_lock(lock_);
  is_assigned_ = false;
  sequence_token_ = SequenceToken();
  sequenced_worker_pool_token_ = SequencedWorkerPool::SequenceToken();
  thread_checker_.DetachFromThread();
}

void SequenceCheckerImpl::EnsureSequenceTokenAssigned() const {
  lock_.AssertAcquired();
  if (is_assigned_)
    return;

  is_assigned_ = true;
  sequence_token_ = SequenceToken::GetForCurrentThread();
  sequenced_worker_pool_token_ =
      SequencedWorkerPool::GetSequenceTokenForCurrentThread();

  // SequencedWorkerPool doesn't use SequenceToken and code outside of
  // SequenceWorkerPool doesn't set a SequencedWorkerPool token.
  DCHECK(!sequence_token_.IsValid() || !sequenced_worker_pool_token_.IsValid());
}

}  // namespace base
